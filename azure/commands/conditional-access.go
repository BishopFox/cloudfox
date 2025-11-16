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
		"Tenant Name", "Tenant ID", "Policy ID", "Policy Name", "State",
		"Included Users", "Excluded Users", "Included Groups", "Excluded Groups",
		"Included Roles", "Excluded Roles", "Included Applications", "Excluded Applications",
		"Included Locations", "Excluded Locations", "Included Platforms", "Client App Types",
		"User Risk Levels", "Sign-in Risk Levels", "Grant Controls", "Session Controls",
		"Created Date", "Modified Date",
	}

	// Generate loot files
	lootFiles := m.generateConditionalAccessLootFiles()

	// -------------------- Check for split by tenant (FIRST) --------------------
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if len(m.PolicyRows) > 0 {
			// Split policies by tenant
			ctx := context.Background()
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.PolicyRows, headers,
				"conditional-access", globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant Conditional Access policies", globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
			}
		}
		// Write loot files separately for multi-tenant (not split)
		if len(lootFiles) > 0 {
			output := ConditionalAccessOutput{
				Table: []internal.TableFile{},
				Loot:  lootFiles,
			}
			scopeType := "tenant"
			scopeIDs := []string{m.TenantID}
			scopeNames := []string{m.TenantName}
			if err := internal.HandleOutputSmart(
				"Azure", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
				scopeType, scopeIDs, scopeNames, m.UserUPN, output,
			); err != nil {
				logger.ErrorM(fmt.Sprintf("Error writing loot output: %v", err), globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
			}
		}
		return
	}

	// -------------------- Non-split case --------------------
	output := ConditionalAccessOutput{
		Table: []internal.TableFile{
			{
				Header: headers,
				Body:   m.PolicyRows,
				Name:   "conditional-access",
			},
		},
		Loot: lootFiles,
	}

	// Determine scope for output (tenant-level for Graph API)
	scopeType := "tenant"
	scopeIDs := []string{m.TenantID}
	scopeNames := []string{m.TenantName}

	// Write output using HandleOutputSmart
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_CONDITIONAL_ACCESS_MODULE_NAME)
		m.CommandCounter.Error++
		return
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

// ======================
// Loot File Generation
// ======================

// generateConditionalAccessLootFiles creates actionable loot files from CA policy data
func (m *ConditionalAccessModule) generateConditionalAccessLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile

	// 1. Weak or disabled policies
	if weakLoot := m.generateWeakPoliciesLoot(); weakLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "conditional-access-weak-policies",
			Contents: weakLoot,
		})
	}

	// 2. Policy coverage gaps
	if gapsLoot := m.generateCoverageGapsLoot(); gapsLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "conditional-access-coverage-gaps",
			Contents: gapsLoot,
		})
	}

	// 3. Bypass opportunities
	if bypassLoot := m.generateBypassOpportunitiesLoot(); bypassLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "conditional-access-bypass-opportunities",
			Contents: bypassLoot,
		})
	}

	// 4. Remediation commands
	if remediationLoot := m.generateRemediationCommandsLoot(); remediationLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "conditional-access-remediation",
			Contents: remediationLoot,
		})
	}

	return lootFiles
}

// generateWeakPoliciesLoot identifies disabled or report-only policies
func (m *ConditionalAccessModule) generateWeakPoliciesLoot() string {
	type WeakPolicy struct {
		PolicyID      string
		PolicyName    string
		State         string
		Scope         string
		GrantControls string
	}

	var weakPolicies []WeakPolicy

	// Scan for disabled or report-only policies
	for _, row := range m.PolicyRows {
		if len(row) < 23 {
			continue
		}

		state := row[4]
		if strings.Contains(state, "Disabled") || strings.Contains(state, "Report-Only") {
			weakPolicies = append(weakPolicies, WeakPolicy{
				PolicyID:      row[2],
				PolicyName:    row[3],
				State:         state,
				Scope:         row[5], // Included Users
				GrantControls: row[19],
			})
		}
	}

	if len(weakPolicies) == 0 {
		return ""
	}

	var loot strings.Builder
	loot.WriteString("# Weak or Disabled Conditional Access Policies\n\n")
	loot.WriteString(fmt.Sprintf("Found %d Conditional Access policies that are disabled or in report-only mode.\n", len(weakPolicies)))
	loot.WriteString("These policies are NOT enforcing security controls and represent gaps in your security posture.\n\n")

	// Separate by type
	disabledPolicies := []WeakPolicy{}
	reportOnlyPolicies := []WeakPolicy{}

	for _, p := range weakPolicies {
		if strings.Contains(p.State, "Disabled") {
			disabledPolicies = append(disabledPolicies, p)
		} else {
			reportOnlyPolicies = append(reportOnlyPolicies, p)
		}
	}

	if len(disabledPolicies) > 0 {
		loot.WriteString("## Disabled Policies (NOT ENFORCED)\n\n")
		for i, policy := range disabledPolicies {
			loot.WriteString(fmt.Sprintf("### %d. %s\n", i+1, policy.PolicyName))
			loot.WriteString(fmt.Sprintf("- **Policy ID**: %s\n", policy.PolicyID))
			loot.WriteString(fmt.Sprintf("- **State**: %s\n", policy.State))
			loot.WriteString(fmt.Sprintf("- **Scope**: %s\n", policy.Scope))
			loot.WriteString(fmt.Sprintf("- **Controls**: %s\n\n", policy.GrantControls))

			loot.WriteString("**⚠ Security Impact**: This policy is completely disabled and provides NO protection.\n\n")

			loot.WriteString("**Enable Policy**:\n")
			loot.WriteString("```bash\n")
			loot.WriteString("# Enable this policy\n")
			loot.WriteString(fmt.Sprintf("az rest --method PATCH \\\n"))
			loot.WriteString(fmt.Sprintf("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/%s\" \\\n", policy.PolicyID))
			loot.WriteString("  --body '{\"state\": \"enabled\"}'\n")
			loot.WriteString("```\n\n")
		}
	}

	if len(reportOnlyPolicies) > 0 {
		loot.WriteString("## Report-Only Policies (MONITORING ONLY)\n\n")
		loot.WriteString("These policies are in report-only mode - they log what WOULD happen but don't block access.\n\n")

		for i, policy := range reportOnlyPolicies {
			loot.WriteString(fmt.Sprintf("### %d. %s\n", i+1, policy.PolicyName))
			loot.WriteString(fmt.Sprintf("- **Policy ID**: %s\n", policy.PolicyID))
			loot.WriteString(fmt.Sprintf("- **State**: %s\n", policy.State))
			loot.WriteString(fmt.Sprintf("- **Scope**: %s\n", policy.Scope))
			loot.WriteString(fmt.Sprintf("- **Controls**: %s\n\n", policy.GrantControls))

			loot.WriteString("**⚠ Security Impact**: This policy only generates logs - attackers can still access resources.\n\n")

			loot.WriteString("**Enable Enforcement**:\n")
			loot.WriteString("```bash\n")
			loot.WriteString("# Move policy from report-only to enabled\n")
			loot.WriteString(fmt.Sprintf("az rest --method PATCH \\\n"))
			loot.WriteString(fmt.Sprintf("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/%s\" \\\n", policy.PolicyID))
			loot.WriteString("  --body '{\"state\": \"enabled\"}'\n")
			loot.WriteString("```\n\n")
		}
	}

	loot.WriteString("## Recommendations\n\n")
	loot.WriteString("1. **Review Disabled Policies** - Determine if they should be enabled or deleted\n")
	loot.WriteString("2. **Promote Report-Only Policies** - After validating they work correctly, enable enforcement\n")
	loot.WriteString("3. **Use Staged Rollout** - Test policy changes with a pilot group before organization-wide deployment\n")
	loot.WriteString("4. **Document Justifications** - If a policy must remain disabled, document why\n\n")

	return loot.String()
}

// generateCoverageGapsLoot identifies missing or weak security controls
func (m *ConditionalAccessModule) generateCoverageGapsLoot() string {
	var loot strings.Builder
	loot.WriteString("# Conditional Access Policy Coverage Gaps\n\n")
	loot.WriteString("Analysis of potential security gaps in your Conditional Access configuration.\n\n")

	// Check for common security controls
	hasMFAPolicy := false
	hasCompliantDevicePolicy := false
	hasLocationPolicy := false
	hasRiskBasedPolicy := false
	hasGuestPolicy := false
	hasLegacyAuthBlockPolicy := false

	for _, row := range m.PolicyRows {
		if len(row) < 23 {
			continue
		}

		state := row[4]
		grantControls := row[19]
		includedUsers := row[5]
		clientAppTypes := row[16]
		userRiskLevels := row[17]
		signInRiskLevels := row[18]
		includedLocations := row[13]

		// Only count enabled policies
		if !strings.Contains(state, "Enabled") {
			continue
		}

		// Check for MFA
		if strings.Contains(grantControls, "MFA") || strings.Contains(grantControls, "mfa") {
			hasMFAPolicy = true
		}

		// Check for compliant device requirement
		if strings.Contains(grantControls, "compliant") || strings.Contains(grantControls, "Compliant") {
			hasCompliantDevicePolicy = true
		}

		// Check for location-based policies
		if !strings.Contains(includedLocations, "Any") && includedLocations != "" {
			hasLocationPolicy = true
		}

		// Check for risk-based policies
		if (userRiskLevels != "Any" && userRiskLevels != "") || (signInRiskLevels != "Any" && signInRiskLevels != "") {
			hasRiskBasedPolicy = true
		}

		// Check for guest-specific policies
		if strings.Contains(includedUsers, "Guest") || strings.Contains(includedUsers, "External") {
			hasGuestPolicy = true
		}

		// Check for legacy auth blocking
		if strings.Contains(clientAppTypes, "other") || strings.Contains(strings.ToLower(clientAppTypes), "legacy") {
			hasLegacyAuthBlockPolicy = true
		}
	}

	// Report gaps
	gaps := []string{}

	if !hasMFAPolicy {
		gaps = append(gaps, "mfa")
		loot.WriteString("## ⚠ CRITICAL: No MFA Policy Detected\n\n")
		loot.WriteString("**Risk**: Users can access resources without multi-factor authentication.\n\n")
		loot.WriteString("**Exploitation**: Attackers with stolen passwords can access all tenant resources.\n\n")
		loot.WriteString("**Remediation**: Create MFA policy for all users\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# Create MFA requirement policy\n")
		loot.WriteString("az rest --method POST \\\n")
		loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" \\\n")
		loot.WriteString("  --body '{\n")
		loot.WriteString("    \"displayName\": \"Require MFA for All Users\",\n")
		loot.WriteString("    \"state\": \"enabled\",\n")
		loot.WriteString("    \"conditions\": {\n")
		loot.WriteString("      \"users\": {\"includeUsers\": [\"All\"]},\n")
		loot.WriteString("      \"applications\": {\"includeApplications\": [\"All\"]}\n")
		loot.WriteString("    },\n")
		loot.WriteString("    \"grantControls\": {\n")
		loot.WriteString("      \"operator\": \"OR\",\n")
		loot.WriteString("      \"builtInControls\": [\"mfa\"]\n")
		loot.WriteString("    }\n")
		loot.WriteString("  }'\n")
		loot.WriteString("```\n\n")
	}

	if !hasCompliantDevicePolicy {
		gaps = append(gaps, "compliant-device")
		loot.WriteString("## ⚠ No Compliant Device Policy\n\n")
		loot.WriteString("**Risk**: Unmanaged or compromised devices can access corporate resources.\n\n")
		loot.WriteString("**Exploitation**: Attackers can use their own devices or compromised personal devices.\n\n")
		loot.WriteString("**Remediation**: Require compliant or Hybrid Azure AD joined devices\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# Create compliant device policy\n")
		loot.WriteString("az rest --method POST \\\n")
		loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" \\\n")
		loot.WriteString("  --body '{\n")
		loot.WriteString("    \"displayName\": \"Require Compliant Device\",\n")
		loot.WriteString("    \"state\": \"enabled\",\n")
		loot.WriteString("    \"conditions\": {\n")
		loot.WriteString("      \"users\": {\"includeUsers\": [\"All\"]},\n")
		loot.WriteString("      \"applications\": {\"includeApplications\": [\"All\"]}\n")
		loot.WriteString("    },\n")
		loot.WriteString("    \"grantControls\": {\n")
		loot.WriteString("      \"operator\": \"OR\",\n")
		loot.WriteString("      \"builtInControls\": [\"compliantDevice\", \"domainJoinedDevice\"]\n")
		loot.WriteString("    }\n")
		loot.WriteString("  }'\n")
		loot.WriteString("```\n\n")
	}

	if !hasLegacyAuthBlockPolicy {
		gaps = append(gaps, "legacy-auth")
		loot.WriteString("## ⚠ No Legacy Authentication Block\n\n")
		loot.WriteString("**Risk**: Legacy protocols (POP, IMAP, SMTP) don't support MFA and can be exploited for password spraying.\n\n")
		loot.WriteString("**Exploitation**: Attackers use legacy auth protocols to bypass MFA requirements.\n\n")
		loot.WriteString("**Remediation**: Block legacy authentication\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# Create legacy auth block policy\n")
		loot.WriteString("az rest --method POST \\\n")
		loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" \\\n")
		loot.WriteString("  --body '{\n")
		loot.WriteString("    \"displayName\": \"Block Legacy Authentication\",\n")
		loot.WriteString("    \"state\": \"enabled\",\n")
		loot.WriteString("    \"conditions\": {\n")
		loot.WriteString("      \"users\": {\"includeUsers\": [\"All\"]},\n")
		loot.WriteString("      \"applications\": {\"includeApplications\": [\"All\"]},\n")
		loot.WriteString("      \"clientAppTypes\": [\"exchangeActiveSync\", \"other\"]\n")
		loot.WriteString("    },\n")
		loot.WriteString("    \"grantControls\": {\n")
		loot.WriteString("      \"builtInControls\": [\"block\"]\n")
		loot.WriteString("    }\n")
		loot.WriteString("  }'\n")
		loot.WriteString("```\n\n")
	}

	if !hasGuestPolicy {
		gaps = append(gaps, "guest-policy")
		loot.WriteString("## ⚠ No Guest/External User Policy\n\n")
		loot.WriteString("**Risk**: External users may have same access as internal users without additional scrutiny.\n\n")
		loot.WriteString("**Recommendation**: Apply stricter controls for guest users (MFA, compliant device, etc.)\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# Create guest-specific MFA policy\n")
		loot.WriteString("az rest --method POST \\\n")
		loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" \\\n")
		loot.WriteString("  --body '{\n")
		loot.WriteString("    \"displayName\": \"Require MFA for Guests\",\n")
		loot.WriteString("    \"state\": \"enabled\",\n")
		loot.WriteString("    \"conditions\": {\n")
		loot.WriteString("      \"users\": {\"includeGuestsOrExternalUsers\": {\"guestOrExternalUserTypes\": \"b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,internalGuest,serviceProvider\"}},\n")
		loot.WriteString("      \"applications\": {\"includeApplications\": [\"All\"]}\n")
		loot.WriteString("    },\n")
		loot.WriteString("    \"grantControls\": {\n")
		loot.WriteString("      \"operator\": \"OR\",\n")
		loot.WriteString("      \"builtInControls\": [\"mfa\"]\n")
		loot.WriteString("    }\n")
		loot.WriteString("  }'\n")
		loot.WriteString("```\n\n")
	}

	if !hasRiskBasedPolicy {
		gaps = append(gaps, "risk-based")
		loot.WriteString("## ℹ No Risk-Based Policies (Requires Azure AD Premium P2)\n\n")
		loot.WriteString("**Opportunity**: Risk-based policies can automatically respond to compromised accounts or risky sign-ins.\n\n")
		loot.WriteString("**Recommendation**: If you have Azure AD Premium P2, implement Identity Protection policies.\n\n")
	}

	if !hasLocationPolicy {
		gaps = append(gaps, "location-based")
		loot.WriteString("## ℹ No Location-Based Policies\n\n")
		loot.WriteString("**Opportunity**: Location-based policies can block access from high-risk countries/regions.\n\n")
		loot.WriteString("**Recommendation**: Create named locations and restrict access from untrusted locations.\n\n")
	}

	if len(gaps) == 0 {
		return "" // No gaps found
	}

	loot.WriteString("## Summary\n\n")
	loot.WriteString(fmt.Sprintf("**Total Gaps Identified**: %d\n\n", len(gaps)))
	loot.WriteString("**Priority Remediation Order**:\n")
	loot.WriteString("1. Block legacy authentication (prevents password spraying)\n")
	loot.WriteString("2. Require MFA for all users (prevents credential compromise)\n")
	loot.WriteString("3. Require compliant devices (prevents malware/unmanaged devices)\n")
	loot.WriteString("4. Implement guest-specific policies (limits external access)\n")
	loot.WriteString("5. Consider risk-based and location-based policies (advanced protection)\n\n")

	return loot.String()
}

// generateBypassOpportunitiesLoot identifies potential policy bypass opportunities
func (m *ConditionalAccessModule) generateBypassOpportunitiesLoot() string {
	type BypassOpportunity struct {
		PolicyID        string
		PolicyName      string
		BypassType      string
		ExcludedItems   string
		ExploitScenario string
	}

	var bypasses []BypassOpportunity

	// Scan for exclusions that could be abused
	for _, row := range m.PolicyRows {
		if len(row) < 23 {
			continue
		}

		state := row[4]
		if !strings.Contains(state, "Enabled") {
			continue
		}

		policyID := row[2]
		policyName := row[3]
		excludedUsers := row[6]
		excludedGroups := row[8]
		excludedRoles := row[10]
		excludedApps := row[12]
		excludedLocations := row[14]

		// Check for excluded users
		if excludedUsers != "None" && excludedUsers != "" {
			bypasses = append(bypasses, BypassOpportunity{
				PolicyID:        policyID,
				PolicyName:      policyName,
				BypassType:      "Excluded Users",
				ExcludedItems:   excludedUsers,
				ExploitScenario: "Compromise or impersonate an excluded user to bypass policy",
			})
		}

		// Check for excluded groups
		if excludedGroups != "None" && excludedGroups != "" {
			bypasses = append(bypasses, BypassOpportunity{
				PolicyID:        policyID,
				PolicyName:      policyName,
				BypassType:      "Excluded Groups",
				ExcludedItems:   excludedGroups,
				ExploitScenario: "Add yourself to an excluded group or compromise a member",
			})
		}

		// Check for excluded roles
		if excludedRoles != "None" && excludedRoles != "" {
			bypasses = append(bypasses, BypassOpportunity{
				PolicyID:        policyID,
				PolicyName:      policyName,
				BypassType:      "Excluded Roles",
				ExcludedItems:   excludedRoles,
				ExploitScenario: "Escalate to an excluded role to bypass policy",
			})
		}

		// Check for excluded applications
		if excludedApps != "None" && excludedApps != "" {
			bypasses = append(bypasses, BypassOpportunity{
				PolicyID:        policyID,
				PolicyName:      policyName,
				BypassType:      "Excluded Applications",
				ExcludedItems:   excludedApps,
				ExploitScenario: "Access resources through excluded application",
			})
		}

		// Check for excluded locations
		if excludedLocations != "None" && excludedLocations != "" {
			bypasses = append(bypasses, BypassOpportunity{
				PolicyID:        policyID,
				PolicyName:      policyName,
				BypassType:      "Excluded Locations",
				ExcludedItems:   excludedLocations,
				ExploitScenario: "VPN to excluded location or spoof IP to bypass policy",
			})
		}
	}

	if len(bypasses) == 0 {
		return ""
	}

	var loot strings.Builder
	loot.WriteString("# Conditional Access Policy Bypass Opportunities\n\n")
	loot.WriteString(fmt.Sprintf("Found %d potential bypass opportunities through policy exclusions.\n", len(bypasses)))
	loot.WriteString("Exclusions are necessary for break-glass scenarios but can be abused if not properly managed.\n\n")

	// Group by bypass type
	bypassMap := make(map[string][]BypassOpportunity)
	for _, bypass := range bypasses {
		bypassMap[bypass.BypassType] = append(bypassMap[bypass.BypassType], bypass)
	}

	// Report each type
	for bypassType, items := range bypassMap {
		loot.WriteString(fmt.Sprintf("## %s (%d policies)\n\n", bypassType, len(items)))

		for i, bypass := range items {
			loot.WriteString(fmt.Sprintf("### %d. %s\n", i+1, bypass.PolicyName))
			loot.WriteString(fmt.Sprintf("- **Policy ID**: %s\n", bypass.PolicyID))
			loot.WriteString(fmt.Sprintf("- **Excluded**: %s\n", bypass.ExcludedItems))
			loot.WriteString(fmt.Sprintf("- **Exploit Scenario**: %s\n\n", bypass.ExploitScenario))

			loot.WriteString("**Investigation Commands**:\n")
			loot.WriteString("```bash\n")
			loot.WriteString(fmt.Sprintf("# Get full policy details\naz rest --method GET --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/%s\"\n", bypass.PolicyID))

			if bypassType == "Excluded Groups" {
				loot.WriteString("\n# List members of excluded groups (example for first group)\n")
				loot.WriteString("# Replace GROUP_ID with actual group ID from policy\n")
				loot.WriteString("az ad group member list --group GROUP_ID --output table\n")
			} else if bypassType == "Excluded Users" {
				loot.WriteString("\n# Get details about excluded users\n")
				loot.WriteString("# Replace USER_ID with actual user ID from policy\n")
				loot.WriteString("az ad user show --id USER_ID --output json\n")
			}

			loot.WriteString("```\n\n")
		}
	}

	loot.WriteString("## Best Practices for Exclusions\n\n")
	loot.WriteString("1. **Break-Glass Accounts Only** - Exclude only emergency admin accounts, not regular users\n")
	loot.WriteString("2. **Monitor Exclusions** - Alert on any use of excluded accounts\n")
	loot.WriteString("3. **Regular Reviews** - Audit exclusions quarterly to ensure they're still necessary\n")
	loot.WriteString("4. **Minimize Scope** - Make exclusions as specific as possible (specific apps, not all apps)\n")
	loot.WriteString("5. **Document Justifications** - Maintain documentation for why each exclusion exists\n")
	loot.WriteString("6. **Privileged Access Management** - Use Azure AD PIM for temporary elevated access instead of permanent exclusions\n\n")

	loot.WriteString("## Attack Scenarios\n\n")
	loot.WriteString("**Scenario 1: Group Membership Manipulation**\n")
	loot.WriteString("```\n")
	loot.WriteString("1. Identify excluded group from CA policy\n")
	loot.WriteString("2. If you have User.ReadWrite.All or Group.ReadWrite.All permissions:\n")
	loot.WriteString("   az ad group member add --group <EXCLUDED_GROUP_ID> --member-id <YOUR_USER_ID>\n")
	loot.WriteString("3. Wait for token refresh (~60 minutes)\n")
	loot.WriteString("4. Policy no longer applies to you - MFA/device compliance bypassed\n")
	loot.WriteString("```\n\n")

	loot.WriteString("**Scenario 2: Role Escalation**\n")
	loot.WriteString("```\n")
	loot.WriteString("1. Identify excluded role from CA policy\n")
	loot.WriteString("2. Escalate to that role through any privilege escalation path\n")
	loot.WriteString("3. Policy no longer applies - access resources without MFA\n")
	loot.WriteString("```\n\n")

	loot.WriteString("**Scenario 3: Location Spoofing**\n")
	loot.WriteString("```\n")
	loot.WriteString("1. Identify excluded location (e.g., corporate IP ranges)\n")
	loot.WriteString("2. VPN to corporate network or spoof IP address\n")
	loot.WriteString("3. Access from \"trusted\" location bypasses additional security controls\n")
	loot.WriteString("```\n\n")

	return loot.String()
}

// generateRemediationCommandsLoot provides commands for strengthening CA policies
func (m *ConditionalAccessModule) generateRemediationCommandsLoot() string {
	var loot strings.Builder
	loot.WriteString("# Conditional Access Policy Remediation Commands\n\n")
	loot.WriteString("Use these commands to investigate, strengthen, and audit Conditional Access policies.\n\n")

	loot.WriteString("## General Investigation Commands\n\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# List all CA policies\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" --output table\n\n")
	loot.WriteString("# Get detailed information about a specific policy\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/POLICY_ID\" --output json\n\n")
	loot.WriteString("# Check CA policy sign-in logs (requires sign-in logs)\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100&$filter=conditionalAccessStatus eq 'failure'\" --output table\n")
	loot.WriteString("```\n\n")

	loot.WriteString("## Enable Disabled/Report-Only Policies\n\n")
	loot.WriteString("```bash\n")

	// Find disabled policies
	disabledCount := 0
	for _, row := range m.PolicyRows {
		if len(row) >= 5 {
			state := row[4]
			if strings.Contains(state, "Disabled") || strings.Contains(state, "Report-Only") {
				disabledCount++
				if disabledCount <= 3 { // Show first 3
					policyID := row[2]
					policyName := row[3]
					loot.WriteString(fmt.Sprintf("# Enable: %s\n", policyName))
					loot.WriteString(fmt.Sprintf("az rest --method PATCH \\\n"))
					loot.WriteString(fmt.Sprintf("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/%s\" \\\n", policyID))
					loot.WriteString("  --body '{\"state\": \"enabled\"}'\n\n")
				}
			}
		}
	}

	if disabledCount > 3 {
		loot.WriteString(fmt.Sprintf("# ... and %d more disabled/report-only policies (see main output)\n", disabledCount-3))
	}

	loot.WriteString("```\n\n")

	loot.WriteString("## Create Essential Baseline Policies\n\n")
	loot.WriteString("**1. Require MFA for All Users**\n")
	loot.WriteString("```bash\n")
	loot.WriteString("az rest --method POST \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" \\\n")
	loot.WriteString("  --body '{\n")
	loot.WriteString("    \"displayName\": \"Baseline: Require MFA for All Users\",\n")
	loot.WriteString("    \"state\": \"enabled\",\n")
	loot.WriteString("    \"conditions\": {\n")
	loot.WriteString("      \"users\": {\"includeUsers\": [\"All\"], \"excludeUsers\": [\"BREAK_GLASS_USER_ID\"]},\n")
	loot.WriteString("      \"applications\": {\"includeApplications\": [\"All\"]}\n")
	loot.WriteString("    },\n")
	loot.WriteString("    \"grantControls\": {\"operator\": \"OR\", \"builtInControls\": [\"mfa\"]}\n")
	loot.WriteString("  }'\n")
	loot.WriteString("```\n\n")

	loot.WriteString("**2. Block Legacy Authentication**\n")
	loot.WriteString("```bash\n")
	loot.WriteString("az rest --method POST \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" \\\n")
	loot.WriteString("  --body '{\n")
	loot.WriteString("    \"displayName\": \"Baseline: Block Legacy Authentication\",\n")
	loot.WriteString("    \"state\": \"enabled\",\n")
	loot.WriteString("    \"conditions\": {\n")
	loot.WriteString("      \"users\": {\"includeUsers\": [\"All\"]},\n")
	loot.WriteString("      \"applications\": {\"includeApplications\": [\"All\"]},\n")
	loot.WriteString("      \"clientAppTypes\": [\"exchangeActiveSync\", \"other\"]\n")
	loot.WriteString("    },\n")
	loot.WriteString("    \"grantControls\": {\"builtInControls\": [\"block\"]}\n")
	loot.WriteString("  }'\n")
	loot.WriteString("```\n\n")

	loot.WriteString("**3. Require Compliant or Hybrid Azure AD Joined Device**\n")
	loot.WriteString("```bash\n")
	loot.WriteString("az rest --method POST \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" \\\n")
	loot.WriteString("  --body '{\n")
	loot.WriteString("    \"displayName\": \"Baseline: Require Compliant or Hybrid Azure AD Joined Device\",\n")
	loot.WriteString("    \"state\": \"enabledForReportingButNotEnforced\",\n")
	loot.WriteString("    \"conditions\": {\n")
	loot.WriteString("      \"users\": {\"includeUsers\": [\"All\"]},\n")
	loot.WriteString("      \"applications\": {\"includeApplications\": [\"Office365\"]}\n")
	loot.WriteString("    },\n")
	loot.WriteString("    \"grantControls\": {\"operator\": \"OR\", \"builtInControls\": [\"compliantDevice\", \"domainJoinedDevice\"]}\n")
	loot.WriteString("  }'\n")
	loot.WriteString("```\n\n")

	loot.WriteString("**4. Require MFA for Azure Management**\n")
	loot.WriteString("```bash\n")
	loot.WriteString("az rest --method POST \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" \\\n")
	loot.WriteString("  --body '{\n")
	loot.WriteString("    \"displayName\": \"Baseline: Require MFA for Azure Management\",\n")
	loot.WriteString("    \"state\": \"enabled\",\n")
	loot.WriteString("    \"conditions\": {\n")
	loot.WriteString("      \"users\": {\"includeUsers\": [\"All\"]},\n")
	loot.WriteString("      \"applications\": {\"includeApplications\": [\"797f4846-ba00-4fd7-ba43-dac1f8f63013\"]}\n")
	loot.WriteString("    },\n")
	loot.WriteString("    \"grantControls\": {\"operator\": \"OR\", \"builtInControls\": [\"mfa\"]}\n")
	loot.WriteString("  }'\n")
	loot.WriteString("# App ID 797f4846-ba00-4fd7-ba43-dac1f8f63013 = Azure Management\n")
	loot.WriteString("```\n\n")

	loot.WriteString("## Audit and Monitoring\n\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# Export all policies for documentation\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\" --output json > ca-policies-backup.json\n\n")
	loot.WriteString("# Check policy changes in audit logs\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=category eq 'Policy'\" --output table\n\n")
	loot.WriteString("# Monitor break-glass account usage\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userPrincipalName eq 'breakglass@domain.com'\" --output table\n\n")
	loot.WriteString("# Find sign-ins that bypassed CA policies\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=conditionalAccessStatus eq 'notApplied'\" --output table\n")
	loot.WriteString("```\n\n")

	loot.WriteString("## Testing and Validation\n\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# Use What If tool to test policy impact\n")
	loot.WriteString("az rest --method POST \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/whatIf\" \\\n")
	loot.WriteString("  --body '{\n")
	loot.WriteString("    \"subject\": {\"userId\": \"USER_ID\"},\n")
	loot.WriteString("    \"includeApplications\": [\"APP_ID\"],\n")
	loot.WriteString("    \"signInType\": \"interactive\",\n")
	loot.WriteString("    \"clientAppType\": \"browser\"\n")
	loot.WriteString("  }'\n")
	loot.WriteString("```\n\n")

	return loot.String()
}
