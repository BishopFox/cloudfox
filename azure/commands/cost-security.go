package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzCostSecurityCommand = &cobra.Command{
	Use:     "cost-security",
	Aliases: []string{"cost-sec", "spending"},
	Short:   "Analyze cost anomalies, budget gaps, and security-cost correlations",
	Long: `
Enumerate cost management and spending patterns with security correlation for a tenant:
./cloudfox az cost-security --tenant TENANT_ID

Enumerate cost management and spending patterns for a subscription:
./cloudfox az cost-security --subscription SUBSCRIPTION_ID

This module analyzes:
- Cost anomalies (crypto mining, unauthorized spending, resource hijacking)
- Budget and alert configuration gaps
- Expensive resources with security misconfigurations
- Orphaned resources (unattached disks, unused IPs, idle VMs)
- Untagged resources for cost allocation visibility
- Spending by resource type and risk level

SECURITY ANALYSIS:
- CRITICAL: Significant cost anomalies (> 200% increase) or no budget controls
- HIGH: Cost anomaly (> 100% increase) or expensive resources with high security risk
- MEDIUM: Budget gaps or moderate cost increases (50-100%)
- INFO: Normal spending patterns with proper budget controls

Use Cases:
- Detect crypto mining and resource abuse (cost spikes)
- Identify budget control gaps for financial security
- Correlate security risk with spending (expensive high-risk resources)
- Find orphaned resources for cost optimization
- Track untagged resources for better cost allocation`,
	Run: ListCostSecurity,
}

// ------------------------------
// Module struct
// ------------------------------
type CostSecurityModule struct {
	azinternal.BaseAzureModule

	Subscriptions         []string
	CostAnomalyRows       [][]string // Cost anomalies per subscription
	BudgetStatusRows      [][]string // Budget and alert configuration
	ExpensiveResourceRows [][]string // Top expensive resources with risk assessment
	OrphanedResourceRows  [][]string // Orphaned/unused resources costing money
	CostByTypeRows        [][]string // Cost breakdown by resource type
	LootMap               map[string]*internal.LootFile
	mu                    sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type CostSecurityOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CostSecurityOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CostSecurityOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListCostSecurity(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_COST_SECURITY_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &CostSecurityModule{
		BaseAzureModule:       azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:         cmdCtx.Subscriptions,
		CostAnomalyRows:       [][]string{},
		BudgetStatusRows:      [][]string{},
		ExpensiveResourceRows: [][]string{},
		OrphanedResourceRows:  [][]string{},
		CostByTypeRows:        [][]string{},
		LootMap: map[string]*internal.LootFile{
			"cost-anomalies":      {Name: "cost-anomalies", Contents: "# Cost Anomalies and Security Incidents\n\n"},
			"budget-gaps":         {Name: "budget-gaps", Contents: "# Budget and Alert Configuration Gaps\n\n"},
			"expensive-high-risk": {Name: "expensive-high-risk", Contents: "# Expensive Resources with High Security Risk\n\n"},
			"orphaned-resources":  {Name: "orphaned-resources", Contents: "# Orphaned Resources Wasting Money\n\n"},
			"cost-optimization":   {Name: "cost-optimization", Contents: "# Cost Optimization Recommendations\n\n"},
		},
	}

	module.PrintCostSecurity(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *CostSecurityModule) PrintCostSecurity(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_COST_SECURITY_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_COST_SECURITY_MODULE_NAME)
			}

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_COST_SECURITY_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		logger.InfoM(fmt.Sprintf("Analyzing cost security for %d subscription(s)", len(m.Subscriptions)), globals.AZ_COST_SECURITY_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_COST_SECURITY_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *CostSecurityModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// 1. Analyze cost anomalies
	m.analyzeCostAnomalies(ctx, subID, subName, logger)

	// 2. Check budget and alert configuration
	m.analyzeBudgetStatus(ctx, subID, subName, logger)

	// 3. Identify expensive resources with security risk
	m.analyzeExpensiveResources(ctx, subID, subName, logger)

	// 4. Find orphaned resources
	m.analyzeOrphanedResources(ctx, subID, subName, logger)

	// 5. Cost breakdown by resource type
	m.analyzeCostByType(ctx, subID, subName, logger)
}

// ------------------------------
// Analyze cost anomalies
// ------------------------------
func (m *CostSecurityModule) analyzeCostAnomalies(ctx context.Context, subID, subName string, logger internal.Logger) {
	anomalies, err := azinternal.GetCostAnomalies(ctx, m.Session, subID)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to analyze cost anomalies: %v", err), globals.AZ_COST_SECURITY_MODULE_NAME)
		}
		return
	}

	for _, anomaly := range anomalies {
		// Determine risk level based on anomaly severity
		riskLevel := "INFO"
		if anomaly.ImpactPercentage > 200 {
			riskLevel = "CRITICAL"
		} else if anomaly.ImpactPercentage > 100 {
			riskLevel = "HIGH"
		} else if anomaly.ImpactPercentage > 50 {
			riskLevel = "MEDIUM"
		}

		m.mu.Lock()
		m.CostAnomalyRows = append(m.CostAnomalyRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			anomaly.DetectionDate,
			anomaly.ResourceType,
			fmt.Sprintf("%.2f%%", anomaly.ImpactPercentage),
			fmt.Sprintf("$%.2f", anomaly.ActualCost),
			fmt.Sprintf("$%.2f", anomaly.ExpectedCost),
			anomaly.AnomalyType,
			riskLevel,
		})

		// Generate loot for critical anomalies
		if riskLevel == "CRITICAL" || riskLevel == "HIGH" {
			if lf, ok := m.LootMap["cost-anomalies"]; ok {
				lf.Contents += fmt.Sprintf("## %s Anomaly: %s\n", riskLevel, anomaly.ResourceType)
				lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
				lf.Contents += fmt.Sprintf("- **Detection Date**: %s\n", anomaly.DetectionDate)
				lf.Contents += fmt.Sprintf("- **Impact**: %.2f%% increase (Expected: $%.2f, Actual: $%.2f)\n", anomaly.ImpactPercentage, anomaly.ExpectedCost, anomaly.ActualCost)
				lf.Contents += fmt.Sprintf("- **Anomaly Type**: %s\n", anomaly.AnomalyType)
				lf.Contents += fmt.Sprintf("- **Potential Cause**: %s\n\n", anomaly.PotentialCause)

				lf.Contents += "### Investigation Commands\n```bash\n"
				lf.Contents += fmt.Sprintf("# Query cost details for anomaly period\n")
				lf.Contents += fmt.Sprintf("az consumption usage list --subscription %s --start-date %s --end-date %s --query \"[?contains(instanceName,'%s')]\" -o table\n\n", subID, anomaly.StartDate, anomaly.EndDate, anomaly.ResourceType)
				lf.Contents += fmt.Sprintf("# List all resources of this type\n")
				lf.Contents += fmt.Sprintf("az resource list --subscription %s --resource-type %s -o table\n", subID, anomaly.ResourceType)
				lf.Contents += "```\n\n"
			}
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Analyze budget status
// ------------------------------
func (m *CostSecurityModule) analyzeBudgetStatus(ctx context.Context, subID, subName string, logger internal.Logger) {
	budgets, err := azinternal.GetBudgetConfiguration(ctx, m.Session, subID)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get budget configuration: %v", err), globals.AZ_COST_SECURITY_MODULE_NAME)
		}
		return
	}

	// Check if subscription has any budgets
	if len(budgets) == 0 {
		m.mu.Lock()
		m.BudgetStatusRows = append(m.BudgetStatusRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			"No Budget",
			"N/A",
			"N/A",
			"No Alerts",
			"CRITICAL",
		})

		if lf, ok := m.LootMap["budget-gaps"]; ok {
			lf.Contents += fmt.Sprintf("## CRITICAL: No Budget Configured\n")
			lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
			lf.Contents += fmt.Sprintf("- **Risk**: Unlimited spending, no financial controls\n")
			lf.Contents += fmt.Sprintf("- **Recommendation**: Create budget with email alerts\n\n")

			lf.Contents += "### Create Budget\n```bash\n"
			lf.Contents += fmt.Sprintf("az consumption budget create --subscription %s --budget-name \"MonthlyBudget\" --amount 1000 --time-grain Monthly --start-date %s\n", subID, time.Now().Format("2006-01-01"))
			lf.Contents += "```\n\n"
		}

		m.mu.Unlock()
		return
	}

	for _, budget := range budgets {
		// Determine risk level
		riskLevel := "INFO"
		if !budget.HasAlerts {
			riskLevel = "HIGH"
		} else if budget.CurrentSpend > budget.Amount*0.9 {
			riskLevel = "MEDIUM"
		}

		m.mu.Lock()
		m.BudgetStatusRows = append(m.BudgetStatusRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			budget.BudgetName,
			fmt.Sprintf("$%.2f", budget.Amount),
			fmt.Sprintf("$%.2f (%.1f%%)", budget.CurrentSpend, (budget.CurrentSpend/budget.Amount)*100),
			budget.AlertStatus,
			riskLevel,
		})

		if riskLevel != "INFO" {
			if lf, ok := m.LootMap["budget-gaps"]; ok {
				lf.Contents += fmt.Sprintf("## %s: Budget \"%s\"\n", riskLevel, budget.BudgetName)
				lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
				lf.Contents += fmt.Sprintf("- **Budget Amount**: $%.2f\n", budget.Amount)
				lf.Contents += fmt.Sprintf("- **Current Spend**: $%.2f (%.1f%%)\n", budget.CurrentSpend, (budget.CurrentSpend/budget.Amount)*100)
				lf.Contents += fmt.Sprintf("- **Alert Status**: %s\n", budget.AlertStatus)

				if !budget.HasAlerts {
					lf.Contents += fmt.Sprintf("- **Issue**: No alerts configured - overspending will go unnoticed\n\n")
				} else {
					lf.Contents += fmt.Sprintf("- **Issue**: Approaching budget limit\n\n")
				}
			}
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Analyze expensive resources
// ------------------------------
func (m *CostSecurityModule) analyzeExpensiveResources(ctx context.Context, subID, subName string, logger internal.Logger) {
	resources, err := azinternal.GetExpensiveResources(ctx, m.Session, subID, 20)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get expensive resources: %v", err), globals.AZ_COST_SECURITY_MODULE_NAME)
		}
		return
	}

	for _, res := range resources {
		// Assess security risk (simplified - actual implementation would check NSG, encryption, etc.)
		securityRisk := res.SecurityRisk // HIGH/MEDIUM/LOW from helper

		// Overall risk combines cost and security
		overallRisk := "INFO"
		if res.MonthlyCost > 1000 && securityRisk == "HIGH" {
			overallRisk = "CRITICAL"
		} else if res.MonthlyCost > 500 && securityRisk == "HIGH" {
			overallRisk = "HIGH"
		} else if res.MonthlyCost > 500 || securityRisk == "HIGH" {
			overallRisk = "MEDIUM"
		}

		m.mu.Lock()
		m.ExpensiveResourceRows = append(m.ExpensiveResourceRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			res.ResourceName,
			res.ResourceType,
			res.Location,
			fmt.Sprintf("$%.2f", res.MonthlyCost),
			securityRisk,
			res.SecurityIssues,
			overallRisk,
		})

		// Generate loot for expensive high-risk resources
		if overallRisk == "CRITICAL" || overallRisk == "HIGH" {
			if lf, ok := m.LootMap["expensive-high-risk"]; ok {
				lf.Contents += fmt.Sprintf("## %s: %s\n", overallRisk, res.ResourceName)
				lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
				lf.Contents += fmt.Sprintf("- **Type**: %s\n", res.ResourceType)
				lf.Contents += fmt.Sprintf("- **Monthly Cost**: $%.2f\n", res.MonthlyCost)
				lf.Contents += fmt.Sprintf("- **Security Risk**: %s\n", securityRisk)
				lf.Contents += fmt.Sprintf("- **Security Issues**: %s\n\n", res.SecurityIssues)

				lf.Contents += "### Recommendation\n"
				lf.Contents += "- Review security configuration to reduce risk\n"
				lf.Contents += "- Consider downsizing or decommissioning if not critical\n"
				lf.Contents += "- Implement proper network controls (NSG, private endpoint)\n\n"
			}
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Analyze orphaned resources
// ------------------------------
func (m *CostSecurityModule) analyzeOrphanedResources(ctx context.Context, subID, subName string, logger internal.Logger) {
	orphaned, err := azinternal.GetOrphanedResources(ctx, m.Session, subID)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get orphaned resources: %v", err), globals.AZ_COST_SECURITY_MODULE_NAME)
		}
		return
	}

	for _, res := range orphaned {
		// Risk based on monthly cost
		riskLevel := "INFO"
		if res.MonthlyCost > 100 {
			riskLevel = "HIGH"
		} else if res.MonthlyCost > 50 {
			riskLevel = "MEDIUM"
		} else if res.MonthlyCost > 0 {
			riskLevel = "LOW"
		}

		m.mu.Lock()
		m.OrphanedResourceRows = append(m.OrphanedResourceRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			res.ResourceName,
			res.ResourceType,
			res.Location,
			res.OrphanReason,
			fmt.Sprintf("$%.2f", res.MonthlyCost),
			fmt.Sprintf("%.0f days", res.DaysOrphaned),
			riskLevel,
		})

		// Generate loot for expensive orphaned resources
		if riskLevel == "HIGH" || riskLevel == "MEDIUM" {
			if lf, ok := m.LootMap["orphaned-resources"]; ok {
				lf.Contents += fmt.Sprintf("## %s: %s (%s)\n", riskLevel, res.ResourceName, res.ResourceType)
				lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
				lf.Contents += fmt.Sprintf("- **Orphan Reason**: %s\n", res.OrphanReason)
				lf.Contents += fmt.Sprintf("- **Monthly Cost**: $%.2f\n", res.MonthlyCost)
				lf.Contents += fmt.Sprintf("- **Days Orphaned**: %.0f\n", res.DaysOrphaned)
				lf.Contents += fmt.Sprintf("- **Annual Waste**: $%.2f\n\n", res.MonthlyCost*12)

				lf.Contents += "### Cleanup Command\n```bash\n"
				lf.Contents += fmt.Sprintf("az resource delete --ids %s\n", res.ResourceID)
				lf.Contents += "```\n\n"
			}
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Analyze cost by resource type
// ------------------------------
func (m *CostSecurityModule) analyzeCostByType(ctx context.Context, subID, subName string, logger internal.Logger) {
	costByType, err := azinternal.GetCostByResourceType(ctx, m.Session, subID)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get cost by type: %v", err), globals.AZ_COST_SECURITY_MODULE_NAME)
		}
		return
	}

	for _, cost := range costByType {
		m.mu.Lock()
		m.CostByTypeRows = append(m.CostByTypeRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			cost.ResourceType,
			fmt.Sprintf("%d", cost.ResourceCount),
			fmt.Sprintf("$%.2f", cost.MonthlyCost),
			fmt.Sprintf("%.1f%%", cost.PercentOfTotal),
			cost.TopConsumers,
		})
		m.mu.Unlock()
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *CostSecurityModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.CostAnomalyRows) == 0 && len(m.BudgetStatusRows) == 0 && len(m.ExpensiveResourceRows) == 0 && len(m.OrphanedResourceRows) == 0 && len(m.CostByTypeRows) == 0 {
		logger.InfoM("No cost security data found", globals.AZ_COST_SECURITY_MODULE_NAME)
		return
	}

	// Build tables
	tables := []internal.TableFile{}

	// Cost Anomalies table
	if len(m.CostAnomalyRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "cost-anomalies",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Detection Date",
				"Resource Type",
				"Impact %",
				"Actual Cost",
				"Expected Cost",
				"Anomaly Type",
				"Risk",
			},
			Body: m.CostAnomalyRows,
		})
	}

	// Budget Status table
	if len(m.BudgetStatusRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "budget-status",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Budget Name",
				"Budget Amount",
				"Current Spend",
				"Alert Status",
				"Risk",
			},
			Body: m.BudgetStatusRows,
		})
	}

	// Expensive Resources table
	if len(m.ExpensiveResourceRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "expensive-resources",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Resource Name",
				"Resource Type",
				"Location",
				"Monthly Cost",
				"Security Risk",
				"Security Issues",
				"Overall Risk",
			},
			Body: m.ExpensiveResourceRows,
		})
	}

	// Orphaned Resources table
	if len(m.OrphanedResourceRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "orphaned-resources",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Resource Name",
				"Resource Type",
				"Location",
				"Orphan Reason",
				"Monthly Cost",
				"Days Orphaned",
				"Risk",
			},
			Body: m.OrphanedResourceRows,
		})
	}

	// Cost by Type table
	if len(m.CostByTypeRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "cost-by-type",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Resource Type",
				"Count",
				"Monthly Cost",
				"% of Total",
				"Top Consumers",
			},
			Body: m.CostByTypeRows,
		})
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" && !strings.HasSuffix(lf.Contents, "\n\n") {
			loot = append(loot, *lf)
		}
	}

	output := CostSecurityOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_COST_SECURITY_MODULE_NAME)
		m.CommandCounter.Error++
	}

	totalRows := len(m.CostAnomalyRows) + len(m.BudgetStatusRows) + len(m.ExpensiveResourceRows) + len(m.OrphanedResourceRows) + len(m.CostByTypeRows)
	logger.SuccessM(fmt.Sprintf("Found %d cost security items across %d subscription(s)", totalRows, len(m.Subscriptions)), globals.AZ_COST_SECURITY_MODULE_NAME)
}
