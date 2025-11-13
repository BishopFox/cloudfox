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
// Cobra command definition
// ------------------------------
var AzConditionalAccessCommand = &cobra.Command{
	Use:     "conditional-access",
	Aliases: []string{"ca", "ca-policies"},
	Short:   "Enumerate Azure Conditional Access Policies",
	Long: `
Enumerate Azure Conditional Access Policies for a specific tenant:
./cloudfox az conditional-access --tenant TENANT_ID

This module provides a policy-centric view of all Conditional Access policies,
including their conditions, grant controls, and assignments. Use this module to:
- Audit all CA policies in the tenant
- Identify disabled or report-only policies
- Analyze policy coverage gaps
- Review policy configurations and security controls`,
	Run: ListConditionalAccessPolicies,
}

// ------------------------------
// Module struct
// ------------------------------
type ConditionalAccessModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	PolicyRows [][]string
	mu         sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ConditionalAccessOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ConditionalAccessOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ConditionalAccessOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListConditionalAccessPolicies(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	// Initialize module
	module := &ConditionalAccessModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		PolicyRows:      [][]string{},
	}

	// Execute module
	module.PrintConditionalAccessPolicies(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *ConditionalAccessModule) PrintConditionalAccessPolicies(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.processTenant(ctx, logger)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.processTenant(ctx, logger)
	}

	// Write output
	m.writeOutput(logger)
}

// ------------------------------
// Process single tenant
// ------------------------------
func (m *ConditionalAccessModule) processTenant(ctx context.Context, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating Conditional Access Policies for tenant: %s", m.TenantName), globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)

	// Get all CA policies
	policies, err := azinternal.GetAllConditionalAccessPolicies(ctx, m.Session)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate CA policies: %v", err), globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	if len(policies) == 0 {
		logger.InfoM(fmt.Sprintf("No Conditional Access policies found for tenant: %s", m.TenantName), globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Found %d Conditional Access policies", len(policies)), globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)

	// Process each policy
	for _, policy := range policies {
		m.processPolicy(ctx, policy)
	}

	m.CommandCounter.Total = len(policies)
	m.CommandCounter.Complete = len(policies)
}

// ------------------------------
// Process individual policy
// ------------------------------
func (m *ConditionalAccessModule) processPolicy(ctx context.Context, policy azinternal.ConditionalAccessPolicyDetails) {
	// Format conditions
	includedUsers := formatSlice(policy.IncludedUsers, "All")
	excludedUsers := formatSlice(policy.ExcludedUsers, "None")
	includedGroups := formatSlice(policy.IncludedGroups, "None")
	excludedGroups := formatSlice(policy.ExcludedGroups, "None")
	includedRoles := formatSlice(policy.IncludedRoles, "None")
	excludedRoles := formatSlice(policy.ExcludedRoles, "None")
	includedApps := formatSlice(policy.IncludedApps, "All")
	excludedApps := formatSlice(policy.ExcludedApps, "None")
	includedLocations := formatSlice(policy.IncludedLocations, "Any")
	excludedLocations := formatSlice(policy.ExcludedLocations, "None")
	includedPlatforms := formatSlice(policy.IncludedPlatforms, "Any")
	clientAppTypes := formatSlice(policy.ClientAppTypes, "Any")
	userRiskLevels := formatSlice(policy.UserRiskLevels, "Any")
	signInRiskLevels := formatSlice(policy.SignInRiskLevels, "Any")

	// Format grant controls
	grantControls := "None"
	if len(policy.GrantControls) > 0 {
		if policy.GrantOperator != "" {
			grantControls = fmt.Sprintf("%s (%s)", strings.Join(policy.GrantControls, ", "), policy.GrantOperator)
		} else {
			grantControls = strings.Join(policy.GrantControls, ", ")
		}
	}

	// Format session controls
	sessionControls := []string{}
	if policy.ApplicationEnforcedRestrictions {
		sessionControls = append(sessionControls, "App Enforced Restrictions")
	}
	if policy.CloudAppSecurity != "" {
		sessionControls = append(sessionControls, fmt.Sprintf("Cloud App Security: %s", policy.CloudAppSecurity))
	}
	if policy.SignInFrequency != "" {
		sessionControls = append(sessionControls, fmt.Sprintf("Sign-in Frequency: %s", policy.SignInFrequency))
	}
	if policy.PersistentBrowser != "" {
		sessionControls = append(sessionControls, fmt.Sprintf("Persistent Browser: %s", policy.PersistentBrowser))
	}
	sessionControlsStr := "None"
	if len(sessionControls) > 0 {
		sessionControlsStr = strings.Join(sessionControls, "; ")
	}

	// Determine policy status indicator
	statusIndicator := ""
	switch policy.State {
	case "enabled":
		statusIndicator = "✓ Enabled"
	case "disabled":
		statusIndicator = "✗ Disabled"
	case "enabledForReportingButNotEnforced":
		statusIndicator = "⚠ Report-Only"
	default:
		statusIndicator = policy.State
	}

	// Thread-safe append
	m.mu.Lock()
	m.PolicyRows = append(m.PolicyRows, []string{
		m.TenantName,
		m.TenantID,
		policy.ID,
		policy.DisplayName,
		statusIndicator,
		includedUsers,
		excludedUsers,
		includedGroups,
		excludedGroups,
		includedRoles,
		excludedRoles,
		includedApps,
		excludedApps,
		includedLocations,
		excludedLocations,
		includedPlatforms,
		clientAppTypes,
		userRiskLevels,
		signInRiskLevels,
		grantControls,
		sessionControlsStr,
		policy.CreatedDateTime,
		policy.ModifiedDateTime,
	})
	m.mu.Unlock()
}

// ------------------------------
// Write output
// ------------------------------
func (m *ConditionalAccessModule) writeOutput(logger internal.Logger) {
	if len(m.PolicyRows) == 0 {
		logger.InfoM("No Conditional Access policies found", globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
		return
	}

	// Define headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Policy ID",
		"Policy Name",
		"State",
		"Included Users",
		"Excluded Users",
		"Included Groups",
		"Excluded Groups",
		"Included Roles",
		"Excluded Roles",
		"Included Applications",
		"Excluded Applications",
		"Included Locations",
		"Excluded Locations",
		"Included Platforms",
		"Client App Types",
		"User Risk Levels",
		"Sign-in Risk Levels",
		"Grant Controls",
		"Session Controls",
		"Created Date",
		"Modified Date",
	}

	// Build output
	output := ConditionalAccessOutput{
		Table: []internal.TableFile{
			{
				Header:    headers,
				Body:      m.PolicyRows,
				TableCols: headers,
				Name:      "conditional-access",
			},
		},
		Loot: []internal.LootFile{},
	}

	// Write table
	if err := internal.WriteFullOutput(
		output,
		m.OutputDirectory,
		m.Verbosity,
		globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME,
		m.AWSProfile,
		m.TenantID,
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Conditional Access Policies for tenant: %s", len(m.PolicyRows), m.TenantName), globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
}

// ------------------------------
// Helper functions
// ------------------------------

// formatSlice formats a string slice for display, replacing empty slices with a default value
func formatSlice(slice []string, defaultValue string) string {
	if len(slice) == 0 {
		return defaultValue
	}

	// Replace special values with user-friendly names
	result := []string{}
	for _, item := range slice {
		switch item {
		case "All":
			result = append(result, "All Users")
		case "None":
			result = append(result, "None")
		case "GuestsOrExternalUsers":
			result = append(result, "Guests/External Users")
		default:
			result = append(result, item)
		}
	}

	return strings.Join(result, ", ")
}
