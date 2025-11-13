package commands

import (
	"context"
	"fmt"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzPolicyCommand = &cobra.Command{
	Use:     "policy",
	Aliases: []string{"policies"},
	Short:   "Enumerate Azure Policy Definitions and Assignments",
	Long: `
Enumerate Azure Policy Definitions and Assignments for a specific tenant:
./cloudfox az policy --tenant TENANT_ID

Enumerate Azure Policy Definitions and Assignments for a specific subscription:
./cloudfox az policy --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListPolicies,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type PolicyModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	PolicyRows    [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type PolicyOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PolicyOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PolicyOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListPolicies(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_POLICY_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &PolicyModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		PolicyRows:      [][]string{},
		LootMap: map[string]*internal.LootFile{
			"policy-definitions": {Name: "policy-definitions", Contents: ""},
			"policy-assignments": {Name: "policy-assignments", Contents: ""},
			"policy-commands":    {Name: "policy-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintPolicies(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *PolicyModule) PrintPolicies(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_POLICY_MODULE_NAME)

		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context for row creation
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_POLICY_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_POLICY_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating policies for %d subscription(s)", len(m.Subscriptions)), globals.AZ_POLICY_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_POLICY_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *PolicyModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Enumerate custom policy definitions
	definitions, err := azinternal.GetCustomPolicyDefinitions(ctx, m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate policy definitions: %v", err), globals.AZ_POLICY_MODULE_NAME)
		}
	}

	// Process each policy definition
	for _, def := range definitions {
		m.mu.Lock()
		m.PolicyRows = append(m.PolicyRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			"N/A", // Resource Group - policies are subscription-scoped
			"N/A", // Region - policies are not region-specific
			def.Name,
			"Definition",
			def.PolicyType,
			def.Mode,
			def.Description,
		})

		// Generate loot - definitions
		if lf, ok := m.LootMap["policy-definitions"]; ok {
			lf.Contents += fmt.Sprintf("## Policy Definition: %s\n", def.Name)
			lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
			lf.Contents += fmt.Sprintf("- **Type**: %s\n", def.PolicyType)
			lf.Contents += fmt.Sprintf("- **Mode**: %s\n", def.Mode)
			lf.Contents += fmt.Sprintf("- **Description**: %s\n\n", def.Description)

			if def.PolicyRule != "" {
				lf.Contents += fmt.Sprintf("### Policy Rule\n```json\n%s\n```\n\n", def.PolicyRule)
			}

			if def.Parameters != "" {
				lf.Contents += fmt.Sprintf("### Parameters\n```json\n%s\n```\n\n", def.Parameters)
			}
		}

		// Generate commands
		if lf, ok := m.LootMap["policy-commands"]; ok {
			lf.Contents += fmt.Sprintf("## Policy Definition: %s\n", def.Name)
			lf.Contents += fmt.Sprintf("az policy definition show --name %s --subscription %s -o json\n", def.Name, subID)
			lf.Contents += fmt.Sprintf("Get-AzPolicyDefinition -Name %s\n\n", def.Name)
		}

		m.mu.Unlock()
	}

	// Enumerate policy assignments
	assignments, err := azinternal.GetPolicyAssignments(ctx, m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate policy assignments: %v", err), globals.AZ_POLICY_MODULE_NAME)
		}
		return
	}

	// Process each policy assignment
	for _, assign := range assignments {
		m.mu.Lock()
		m.PolicyRows = append(m.PolicyRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			"N/A", // Resource Group - assignments can be at various scopes
			"N/A", // Region - policies are not region-specific
			assign.Name,
			"Assignment",
			assign.PolicyDefinitionName,
			assign.Scope,
			assign.Description,
		})

		// Generate loot - assignments
		if lf, ok := m.LootMap["policy-assignments"]; ok {
			lf.Contents += fmt.Sprintf("## Policy Assignment: %s\n", assign.Name)
			lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
			lf.Contents += fmt.Sprintf("- **Policy Definition**: %s\n", assign.PolicyDefinitionName)
			lf.Contents += fmt.Sprintf("- **Scope**: %s\n", assign.Scope)
			lf.Contents += fmt.Sprintf("- **Description**: %s\n\n", assign.Description)

			if assign.Parameters != "" {
				lf.Contents += fmt.Sprintf("### Assignment Parameters\n```json\n%s\n```\n\n", assign.Parameters)
			}
		}

		// Generate commands
		if lf, ok := m.LootMap["policy-commands"]; ok {
			lf.Contents += fmt.Sprintf("## Policy Assignment: %s\n", assign.Name)
			lf.Contents += fmt.Sprintf("az policy assignment show --name %s --scope %s -o json\n", assign.Name, assign.Scope)
			lf.Contents += fmt.Sprintf("Get-AzPolicyAssignment -Name %s\n\n", assign.Name)
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *PolicyModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.PolicyRows) == 0 {
		logger.InfoM("No custom policies or assignments found", globals.AZ_POLICY_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Policy Name",
		"Type",
		"Policy/Definition",
		"Mode/Scope",
		"Description",
	}

	// Check if we should split output by tenant (multi-tenant takes precedence)
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.PolicyRows, headers,
			"policies", globals.AZ_POLICY_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise, check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.PolicyRows, headers,
			"policies", globals.AZ_POLICY_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := PolicyOutput{
		Table: []internal.TableFile{{
			Name:   "policies",
			Header: headers,
			Body:   m.PolicyRows,
		}},
		Loot: loot,
	}

	// Determine output scope (single subscription vs tenant-wide consolidation)
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart (automatic streaming for large datasets)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_POLICY_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d policy definition(s) and assignment(s) across %d subscription(s)", len(m.PolicyRows), len(m.Subscriptions)), globals.AZ_POLICY_MODULE_NAME)
}
