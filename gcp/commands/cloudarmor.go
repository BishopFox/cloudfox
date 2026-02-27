package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	cloudarmorservice "github.com/BishopFox/cloudfox/gcp/services/cloudArmorService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCloudArmorCommand = &cobra.Command{
	Use:     globals.GCP_CLOUDARMOR_MODULE_NAME,
	Aliases: []string{"armor", "waf", "security-policies"},
	Short:   "Enumerate Cloud Armor security policies and find weaknesses",
	Long: `Enumerate Cloud Armor security policies and identify misconfigurations.

Cloud Armor provides DDoS protection and WAF (Web Application Firewall) capabilities
for Google Cloud load balancers.

Security Relevance:
- Misconfigured policies may not actually block attacks
- Preview-only rules don't block, just log
- Missing OWASP rules leave apps vulnerable to common attacks
- Unprotected load balancers have no WAF protection

What this module finds:
- All Cloud Armor security policies
- Policy weaknesses and misconfigurations
- Rules in preview mode (not blocking)
- Load balancers without Cloud Armor protection
- Missing adaptive protection (DDoS)`,
	Run: runGCPCloudArmorCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CloudArmorModule struct {
	gcpinternal.BaseGCPModule

	ProjectPolicies map[string][]cloudarmorservice.SecurityPolicy // projectID -> policies
	UnprotectedLBs  map[string][]string                           // projectID -> LB names
	mu              sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CloudArmorOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CloudArmorOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CloudArmorOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCloudArmorCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CLOUDARMOR_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CloudArmorModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectPolicies: make(map[string][]cloudarmorservice.SecurityPolicy),
		UnprotectedLBs:  make(map[string][]string),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CloudArmorModule) getAllPolicies() []cloudarmorservice.SecurityPolicy {
	var all []cloudarmorservice.SecurityPolicy
	for _, policies := range m.ProjectPolicies {
		all = append(all, policies...)
	}
	return all
}

func (m *CloudArmorModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CLOUDARMOR_MODULE_NAME, m.processProject)

	// Count unprotected LBs
	totalUnprotected := 0
	for _, lbs := range m.UnprotectedLBs {
		totalUnprotected += len(lbs)
	}

	allPolicies := m.getAllPolicies()
	if len(allPolicies) == 0 && totalUnprotected == 0 {
		logger.InfoM("No Cloud Armor policies found", globals.GCP_CLOUDARMOR_MODULE_NAME)
		return
	}

	// Count policies with weaknesses
	weakPolicies := 0
	for _, policy := range allPolicies {
		if len(policy.Weaknesses) > 0 {
			weakPolicies++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d security policy(ies), %d with weaknesses, %d unprotected LB(s)",
		len(allPolicies), weakPolicies, totalUnprotected), globals.GCP_CLOUDARMOR_MODULE_NAME)

	if totalUnprotected > 0 {
		logger.InfoM(fmt.Sprintf("[MEDIUM] %d load balancer(s) have no Cloud Armor protection", totalUnprotected), globals.GCP_CLOUDARMOR_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CloudArmorModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking Cloud Armor in project: %s", projectID), globals.GCP_CLOUDARMOR_MODULE_NAME)
	}

	svc := cloudarmorservice.New()

	// Get security policies
	policies, err := svc.GetSecurityPolicies(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDARMOR_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Armor security policies in project %s", projectID))
	}

	// Get unprotected LBs
	unprotectedLBs, err := svc.GetUnprotectedLoadBalancers(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDARMOR_MODULE_NAME,
			fmt.Sprintf("Could not enumerate unprotected load balancers in project %s", projectID))
	}

	m.mu.Lock()
	m.ProjectPolicies[projectID] = policies
	if len(unprotectedLBs) > 0 {
		m.UnprotectedLBs[projectID] = unprotectedLBs
	}
	m.mu.Unlock()
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudArmorModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *CloudArmorModule) getPoliciesHeader() []string {
	return []string{"Project", "Policy", "Type", "Rules", "Adaptive", "DDoS", "Attached To", "Weaknesses"}
}

func (m *CloudArmorModule) getRulesHeader() []string {
	return []string{"Project", "Policy", "Priority", "Action", "Preview", "Match", "Rate Limit"}
}

func (m *CloudArmorModule) getUnprotectedLBsHeader() []string {
	return []string{"Project", "Backend Service", "Status"}
}

func (m *CloudArmorModule) policiesToTableBody(policies []cloudarmorservice.SecurityPolicy) [][]string {
	var body [][]string
	for _, policy := range policies {
		adaptive := "No"
		if policy.AdaptiveProtection {
			adaptive = "Yes"
		}

		ddos := "-"
		if policy.DDOSProtection != "" {
			ddos = policy.DDOSProtection
		}

		resources := "-"
		if len(policy.AttachedResources) > 0 {
			resources = strings.Join(policy.AttachedResources, ", ")
		}

		weaknesses := "-"
		if len(policy.Weaknesses) > 0 {
			weaknesses = strings.Join(policy.Weaknesses, "; ")
		}

		body = append(body, []string{
			m.GetProjectName(policy.ProjectID),
			policy.Name,
			policy.Type,
			fmt.Sprintf("%d", policy.RuleCount),
			adaptive,
			ddos,
			resources,
			weaknesses,
		})
	}
	return body
}

func (m *CloudArmorModule) rulesToTableBody(policies []cloudarmorservice.SecurityPolicy) [][]string {
	var body [][]string
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			preview := "No"
			if rule.Preview {
				preview = "Yes"
			}

			rateLimit := "-"
			if rule.RateLimitConfig != nil {
				rateLimit = fmt.Sprintf("%d/%ds", rule.RateLimitConfig.ThresholdCount, rule.RateLimitConfig.IntervalSec)
			}

			match := rule.Match
			if len(match) > 80 {
				match = match[:77] + "..."
			}

			body = append(body, []string{
				m.GetProjectName(policy.ProjectID),
				policy.Name,
				fmt.Sprintf("%d", rule.Priority),
				rule.Action,
				preview,
				match,
				rateLimit,
			})
		}
	}
	return body
}

func (m *CloudArmorModule) unprotectedLBsToTableBody(projectID string, lbs []string) [][]string {
	var body [][]string
	for _, lb := range lbs {
		body = append(body, []string{
			m.GetProjectName(projectID),
			lb,
			"UNPROTECTED",
		})
	}
	return body
}

func (m *CloudArmorModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if policies, ok := m.ProjectPolicies[projectID]; ok && len(policies) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "security-policies",
			Header: m.getPoliciesHeader(),
			Body:   m.policiesToTableBody(policies),
		})

		// Add rules table if there are rules
		rulesBody := m.rulesToTableBody(policies)
		if len(rulesBody) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "security-policy-rules",
				Header: m.getRulesHeader(),
				Body:   rulesBody,
			})
		}
	}

	if lbs, ok := m.UnprotectedLBs[projectID]; ok && len(lbs) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "unprotected-backend-services",
			Header: m.getUnprotectedLBsHeader(),
			Body:   m.unprotectedLBsToTableBody(projectID, lbs),
		})
	}

	return tableFiles
}

func (m *CloudArmorModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Get all project IDs that have data
	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectPolicies {
		projectIDs[projectID] = true
	}
	for projectID := range m.UnprotectedLBs {
		projectIDs[projectID] = true
	}

	for projectID := range projectIDs {
		tableFiles := m.buildTablesForProject(projectID)
		outputData.ProjectLevelData[projectID] = CloudArmorOutput{Table: tableFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_CLOUDARMOR_MODULE_NAME)
	}
}

func (m *CloudArmorModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	allPolicies := m.getAllPolicies()
	if len(allPolicies) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "security-policies",
			Header: m.getPoliciesHeader(),
			Body:   m.policiesToTableBody(allPolicies),
		})
	}

	// Add rules table if there are rules
	if len(allPolicies) > 0 {
		rulesBody := m.rulesToTableBody(allPolicies)
		if len(rulesBody) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "security-policy-rules",
				Header: m.getRulesHeader(),
				Body:   rulesBody,
			})
		}
	}

	// Build unprotected LBs table from all projects
	var allUnprotectedBody [][]string
	for projectID, lbs := range m.UnprotectedLBs {
		allUnprotectedBody = append(allUnprotectedBody, m.unprotectedLBsToTableBody(projectID, lbs)...)
	}
	if len(allUnprotectedBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "unprotected-backend-services",
			Header: m.getUnprotectedLBsHeader(),
			Body:   allUnprotectedBody,
		})
	}

	output := CloudArmorOutput{Table: tables}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, scopeNames, m.Account, output)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDARMOR_MODULE_NAME)
	}
}
