package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzComplianceDashboardCommand = &cobra.Command{
	Use:     "compliance-dashboard",
	Aliases: []string{"compliance", "comp-dash"},
	Short:   "Comprehensive Azure Policy compliance and regulatory standards dashboard",
	Long: `
Enumerate Azure Policy compliance state and regulatory standards for a specific tenant:
./cloudfox az compliance-dashboard --tenant TENANT_ID

Enumerate Azure Policy compliance and regulatory standards for a specific subscription:
./cloudfox az compliance-dashboard --subscription SUBSCRIPTION_ID

This module provides a comprehensive compliance dashboard including:
- Policy compliance state (compliant vs non-compliant resources per policy)
- Regulatory compliance standards (PCI-DSS, ISO 27001, HIPAA, CIS, NIST, etc.)
- Compliance percentage per standard and control
- Non-compliant resources requiring remediation
- Initiative compliance (Azure Policy initiatives)

SECURITY ANALYSIS:
- CRITICAL: Multiple critical controls non-compliant (> 5 failed critical controls)
- HIGH: Critical control failures or < 50% compliance on regulatory standard
- MEDIUM: Important controls non-compliant or 50-80% compliance
- INFO: > 80% compliance, minor improvements needed

Use Cases:
- Audit readiness for PCI-DSS, ISO 27001, HIPAA certifications
- Security posture assessment against CIS benchmarks
- Identify non-compliant resources for remediation
- Track compliance improvement over time`,
	Run: ListComplianceDashboard,
}

// ------------------------------
// Module struct
// ------------------------------
type ComplianceDashboardModule struct {
	azinternal.BaseAzureModule

	Subscriptions            []string
	PolicyComplianceRows     [][]string // Policy compliance state per policy
	RegulatoryComplianceRows [][]string // Regulatory standards (PCI-DSS, ISO, etc.)
	InitiativeComplianceRows [][]string // Policy initiative compliance
	NonCompliantResourceRows [][]string // Sample of non-compliant resources
	LootMap                  map[string]*internal.LootFile
	mu                       sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ComplianceDashboardOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ComplianceDashboardOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ComplianceDashboardOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListComplianceDashboard(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &ComplianceDashboardModule{
		BaseAzureModule:          azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:            cmdCtx.Subscriptions,
		PolicyComplianceRows:     [][]string{},
		RegulatoryComplianceRows: [][]string{},
		InitiativeComplianceRows: [][]string{},
		NonCompliantResourceRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"compliance-critical-failures":      {Name: "compliance-critical-failures", Contents: "# Critical Compliance Failures\n\n"},
			"compliance-noncompliant-resources": {Name: "compliance-noncompliant-resources", Contents: "# Non-Compliant Resources by Policy\n\n"},
			"compliance-regulatory-gaps":        {Name: "compliance-regulatory-gaps", Contents: "# Regulatory Compliance Gaps\n\n"},
			"compliance-remediation-commands":   {Name: "compliance-remediation-commands", Contents: "# Compliance Remediation Commands\n\n"},
			"compliance-audit-report":           {Name: "compliance-audit-report", Contents: "# Compliance Audit Report\n\n"},
		},
	}

	module.PrintComplianceDashboard(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *ComplianceDashboardModule) PrintComplianceDashboard(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
			}

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		logger.InfoM(fmt.Sprintf("Enumerating compliance state for %d subscription(s)", len(m.Subscriptions)), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *ComplianceDashboardModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// 1. Enumerate policy compliance state
	m.enumeratePolicyCompliance(ctx, subID, subName, logger)

	// 2. Enumerate regulatory compliance standards
	m.enumerateRegulatoryCompliance(ctx, subID, subName, logger)

	// 3. Enumerate policy initiative compliance
	m.enumerateInitiativeCompliance(ctx, subID, subName, logger)

	// 4. Sample non-compliant resources (limit to 20 per subscription)
	m.enumerateNonCompliantResources(ctx, subID, subName, logger)
}

// ------------------------------
// Enumerate policy compliance state
// ------------------------------
func (m *ComplianceDashboardModule) enumeratePolicyCompliance(ctx context.Context, subID, subName string, logger internal.Logger) {
	policyStates, err := azinternal.GetPolicyComplianceState(ctx, m.Session, subID)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate policy compliance: %v", err), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
		}
		return
	}

	for _, state := range policyStates {
		// Calculate compliance percentage
		totalResources := state.CompliantResources + state.NonCompliantResources
		compliancePercent := 0.0
		if totalResources > 0 {
			compliancePercent = (float64(state.CompliantResources) / float64(totalResources)) * 100
		}

		// Determine risk level
		riskLevel := "INFO"
		if state.NonCompliantResources > 0 {
			if compliancePercent < 50 {
				riskLevel = "HIGH"
			} else if compliancePercent < 80 {
				riskLevel = "MEDIUM"
			} else {
				riskLevel = "LOW"
			}
		}

		m.mu.Lock()
		m.PolicyComplianceRows = append(m.PolicyComplianceRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			state.PolicyDefinitionName,
			state.PolicyAssignmentName,
			fmt.Sprintf("%d", state.CompliantResources),
			fmt.Sprintf("%d", state.NonCompliantResources),
			fmt.Sprintf("%.1f%%", compliancePercent),
			riskLevel,
		})

		// Generate loot for non-compliant policies
		if state.NonCompliantResources > 0 {
			if lf, ok := m.LootMap["compliance-noncompliant-resources"]; ok {
				lf.Contents += fmt.Sprintf("## Policy: %s\n", state.PolicyDefinitionName)
				lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
				lf.Contents += fmt.Sprintf("- **Assignment**: %s\n", state.PolicyAssignmentName)
				lf.Contents += fmt.Sprintf("- **Non-Compliant Resources**: %d\n", state.NonCompliantResources)
				lf.Contents += fmt.Sprintf("- **Compliance**: %.1f%%\n", compliancePercent)
				lf.Contents += fmt.Sprintf("- **Risk**: %s\n\n", riskLevel)

				lf.Contents += "### Query Non-Compliant Resources\n```bash\n"
				lf.Contents += fmt.Sprintf("az policy state list --subscription %s --filter \"policyAssignmentName eq '%s' and complianceState eq 'NonCompliant'\" -o table\n", subID, state.PolicyAssignmentName)
				lf.Contents += "```\n\n"
			}

			if riskLevel == "HIGH" || riskLevel == "CRITICAL" {
				if lf, ok := m.LootMap["compliance-critical-failures"]; ok {
					lf.Contents += fmt.Sprintf("- **%s** - %d non-compliant resources (%.1f%% compliance)\n", state.PolicyDefinitionName, state.NonCompliantResources, compliancePercent)
					lf.Contents += fmt.Sprintf("  - Subscription: %s (%s)\n", subName, subID)
					lf.Contents += fmt.Sprintf("  - Assignment: %s\n\n", state.PolicyAssignmentName)
				}
			}
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Enumerate regulatory compliance
// ------------------------------
func (m *ComplianceDashboardModule) enumerateRegulatoryCompliance(ctx context.Context, subID, subName string, logger internal.Logger) {
	standards, err := azinternal.GetRegulatoryComplianceStandards(ctx, m.Session, subID)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate regulatory compliance: %v", err), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
		}
		return
	}

	for _, std := range standards {
		// Calculate compliance metrics
		totalControls := std.PassedControls + std.FailedControls + std.SkippedControls
		compliancePercent := 0.0
		if totalControls > 0 {
			compliancePercent = (float64(std.PassedControls) / float64(totalControls)) * 100
		}

		// Determine risk level based on failed controls and compliance percentage
		riskLevel := "INFO"
		if std.FailedControls > 5 && strings.Contains(strings.ToLower(std.Severity), "critical") {
			riskLevel = "CRITICAL"
		} else if std.FailedControls > 0 && compliancePercent < 50 {
			riskLevel = "HIGH"
		} else if std.FailedControls > 0 && compliancePercent < 80 {
			riskLevel = "MEDIUM"
		} else if std.FailedControls > 0 {
			riskLevel = "LOW"
		}

		m.mu.Lock()
		m.RegulatoryComplianceRows = append(m.RegulatoryComplianceRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			std.StandardName,
			std.Description,
			fmt.Sprintf("%d", std.PassedControls),
			fmt.Sprintf("%d", std.FailedControls),
			fmt.Sprintf("%d", std.SkippedControls),
			fmt.Sprintf("%.1f%%", compliancePercent),
			std.State,
			riskLevel,
		})

		// Generate loot for regulatory gaps
		if std.FailedControls > 0 {
			if lf, ok := m.LootMap["compliance-regulatory-gaps"]; ok {
				lf.Contents += fmt.Sprintf("## Regulatory Standard: %s\n", std.StandardName)
				lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
				lf.Contents += fmt.Sprintf("- **Description**: %s\n", std.Description)
				lf.Contents += fmt.Sprintf("- **Failed Controls**: %d\n", std.FailedControls)
				lf.Contents += fmt.Sprintf("- **Compliance**: %.1f%%\n", compliancePercent)
				lf.Contents += fmt.Sprintf("- **Risk**: %s\n\n", riskLevel)

				lf.Contents += "### View Failed Controls\n```bash\n"
				lf.Contents += fmt.Sprintf("az security regulatory-compliance-controls list --standard-name '%s' --filter \"state eq 'Failed'\" -o table\n", std.StandardName)
				lf.Contents += "```\n\n"
			}

			if lf, ok := m.LootMap["compliance-audit-report"]; ok {
				lf.Contents += fmt.Sprintf("### %s\n", std.StandardName)
				lf.Contents += fmt.Sprintf("- Compliance: %.1f%% (%d passed, %d failed, %d skipped)\n", compliancePercent, std.PassedControls, std.FailedControls, std.SkippedControls)
				lf.Contents += fmt.Sprintf("- State: %s\n", std.State)
				lf.Contents += fmt.Sprintf("- Risk Level: %s\n\n", riskLevel)
			}
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Enumerate policy initiative compliance
// ------------------------------
func (m *ComplianceDashboardModule) enumerateInitiativeCompliance(ctx context.Context, subID, subName string, logger internal.Logger) {
	initiatives, err := azinternal.GetPolicyInitiativeCompliance(ctx, m.Session, subID)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate initiative compliance: %v", err), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
		}
		return
	}

	for _, init := range initiatives {
		// Calculate compliance metrics
		totalPolicies := init.CompliantPolicies + init.NonCompliantPolicies
		compliancePercent := 0.0
		if totalPolicies > 0 {
			compliancePercent = (float64(init.CompliantPolicies) / float64(totalPolicies)) * 100
		}

		// Determine risk level
		riskLevel := "INFO"
		if init.NonCompliantPolicies > 0 {
			if compliancePercent < 50 {
				riskLevel = "HIGH"
			} else if compliancePercent < 80 {
				riskLevel = "MEDIUM"
			} else {
				riskLevel = "LOW"
			}
		}

		m.mu.Lock()
		m.InitiativeComplianceRows = append(m.InitiativeComplianceRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			init.InitiativeName,
			init.Description,
			fmt.Sprintf("%d", init.CompliantPolicies),
			fmt.Sprintf("%d", init.NonCompliantPolicies),
			fmt.Sprintf("%d", init.TotalResources),
			fmt.Sprintf("%d", init.NonCompliantResources),
			fmt.Sprintf("%.1f%%", compliancePercent),
			riskLevel,
		})

		// Generate remediation commands
		if init.NonCompliantPolicies > 0 {
			if lf, ok := m.LootMap["compliance-remediation-commands"]; ok {
				lf.Contents += fmt.Sprintf("## Initiative: %s\n", init.InitiativeName)
				lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
				lf.Contents += fmt.Sprintf("- **Non-Compliant Policies**: %d/%d\n", init.NonCompliantPolicies, totalPolicies)
				lf.Contents += fmt.Sprintf("- **Non-Compliant Resources**: %d\n\n", init.NonCompliantResources)

				lf.Contents += "### List Non-Compliant Policies in Initiative\n```bash\n"
				lf.Contents += fmt.Sprintf("az policy state list --subscription %s --filter \"policySetDefinitionName eq '%s' and complianceState eq 'NonCompliant'\" --apply groupby((policyDefinitionName)) -o table\n", subID, init.InitiativeName)
				lf.Contents += "```\n\n"

				lf.Contents += "### Trigger Compliance Scan\n```bash\n"
				lf.Contents += fmt.Sprintf("az policy state trigger-scan --subscription %s --no-wait\n", subID)
				lf.Contents += "```\n\n"
			}
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Enumerate sample non-compliant resources
// ------------------------------
func (m *ComplianceDashboardModule) enumerateNonCompliantResources(ctx context.Context, subID, subName string, logger internal.Logger) {
	resources, err := azinternal.GetNonCompliantResourcesSample(ctx, m.Session, subID, 20)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate non-compliant resources: %v", err), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
		}
		return
	}

	for _, res := range resources {
		m.mu.Lock()
		m.NonCompliantResourceRows = append(m.NonCompliantResourceRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			res.ResourceID,
			res.ResourceType,
			res.ResourceLocation,
			res.PolicyDefinitionName,
			res.PolicyAssignmentName,
			res.ComplianceState,
		})
		m.mu.Unlock()
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *ComplianceDashboardModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.PolicyComplianceRows) == 0 && len(m.RegulatoryComplianceRows) == 0 && len(m.InitiativeComplianceRows) == 0 {
		logger.InfoM("No compliance data found", globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
		return
	}

	// Build tables
	tables := []internal.TableFile{}

	// Policy Compliance table
	if len(m.PolicyComplianceRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "policy-compliance",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Policy Definition",
				"Policy Assignment",
				"Compliant Resources",
				"Non-Compliant Resources",
				"Compliance %",
				"Risk",
			},
			Body: m.PolicyComplianceRows,
		})
	}

	// Regulatory Compliance table
	if len(m.RegulatoryComplianceRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "regulatory-compliance",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Standard Name",
				"Description",
				"Passed Controls",
				"Failed Controls",
				"Skipped Controls",
				"Compliance %",
				"State",
				"Risk",
			},
			Body: m.RegulatoryComplianceRows,
		})
	}

	// Initiative Compliance table
	if len(m.InitiativeComplianceRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "initiative-compliance",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Initiative Name",
				"Description",
				"Compliant Policies",
				"Non-Compliant Policies",
				"Total Resources",
				"Non-Compliant Resources",
				"Compliance %",
				"Risk",
			},
			Body: m.InitiativeComplianceRows,
		})
	}

	// Non-Compliant Resources sample table
	if len(m.NonCompliantResourceRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "noncompliant-resources-sample",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Resource ID",
				"Resource Type",
				"Location",
				"Policy Definition",
				"Policy Assignment",
				"Compliance State",
			},
			Body: m.NonCompliantResourceRows,
		})
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" && !strings.HasSuffix(lf.Contents, "\n\n") {
			loot = append(loot, *lf)
		}
	}

	output := ComplianceDashboardOutput{
		Table: tables,
		Loot:  loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
		m.CommandCounter.Error++
	}

	totalRows := len(m.PolicyComplianceRows) + len(m.RegulatoryComplianceRows) + len(m.InitiativeComplianceRows) + len(m.NonCompliantResourceRows)
	logger.SuccessM(fmt.Sprintf("Found %d compliance items across %d subscription(s)", totalRows, len(m.Subscriptions)), globals.AZ_COMPLIANCE_DASHBOARD_MODULE_NAME)
}
