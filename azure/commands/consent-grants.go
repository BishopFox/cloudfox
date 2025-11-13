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
var AzConsentGrantsCommand = &cobra.Command{
	Use:     "consent-grants",
	Aliases: []string{"consent", "oauth-grants"},
	Short:   "Enumerate OAuth2 Consent Grants",
	Long: `
Enumerate OAuth2 Consent Grants for a specific tenant:
./cloudfox az consent-grants --tenant TENANT_ID

This module provides a consent-centric view of all OAuth2 permission grants,
including admin consent vs user consent, risky permissions, and external apps.
Use this module to:
- Audit all consent grants in the tenant
- Identify user consent vs admin consent
- Flag risky permissions (Mail.ReadWrite, Directory.ReadWrite.All, etc.)
- Find external/multi-tenant apps with access
- Identify users who granted consent to risky apps`,
	Run: ListConsentGrants,
}

// ------------------------------
// Module struct
// ------------------------------
type ConsentGrantsModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	GrantRows [][]string
	mu        sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ConsentGrantsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ConsentGrantsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ConsentGrantsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListConsentGrants(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_CONSENT_GRANTS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	// Initialize module
	module := &ConsentGrantsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		GrantRows:       [][]string{},
	}

	// Execute module
	module.PrintConsentGrants(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *ConsentGrantsModule) PrintConsentGrants(ctx context.Context, logger internal.Logger) {
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
func (m *ConsentGrantsModule) processTenant(ctx context.Context, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating OAuth2 Consent Grants for tenant: %s", m.TenantName), globals.AZ_CONSENT_GRANTS_MODULE_NAME)

	// Get all consent grants
	grants, err := azinternal.GetAllOAuth2PermissionGrants(ctx, m.Session)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate consent grants: %v", err), globals.AZ_CONSENT_GRANTS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	if len(grants) == 0 {
		logger.InfoM(fmt.Sprintf("No OAuth2 consent grants found for tenant: %s", m.TenantName), globals.AZ_CONSENT_GRANTS_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Found %d OAuth2 consent grants", len(grants)), globals.AZ_CONSENT_GRANTS_MODULE_NAME)

	// Process each grant
	for _, grant := range grants {
		m.processGrant(ctx, grant)
	}

	m.CommandCounter.Total = len(grants)
	m.CommandCounter.Complete = len(grants)
}

// ------------------------------
// Process individual consent grant
// ------------------------------
func (m *ConsentGrantsModule) processGrant(ctx context.Context, grant azinternal.OAuth2PermissionGrantDetails) {
	// Format consent type with indicator
	consentTypeDisplay := ""
	switch grant.ConsentType {
	case "AllPrincipals":
		consentTypeDisplay = "✓ Admin Consent"
	case "Principal":
		consentTypeDisplay = "⚠ User Consent"
	default:
		consentTypeDisplay = grant.ConsentType
	}

	// Format principal (user who granted consent)
	principalDisplay := "N/A (Admin Consent)"
	if grant.ConsentType == "Principal" && grant.PrincipalName != "" {
		principalDisplay = grant.PrincipalName
	} else if grant.ConsentType == "Principal" && grant.PrincipalID != "" {
		principalDisplay = grant.PrincipalID
	}

	// Format permissions/scopes
	scopesDisplay := "None"
	if len(grant.Scopes) > 0 {
		scopesDisplay = strings.Join(grant.Scopes, ", ")
	}

	// Format risky permissions
	riskyPermsDisplay := "None"
	riskyIndicator := "✓ Safe"
	if grant.IsRisky && len(grant.RiskyPermissions) > 0 {
		riskyPermsDisplay = strings.Join(grant.RiskyPermissions, "; ")
		riskyIndicator = "⚠ RISKY"
	}

	// External app indicator
	externalIndicator := "Internal"
	if grant.IsExternal {
		externalIndicator = "⚠ External/Multi-tenant"
	}

	// Client display name
	clientName := grant.ClientDisplayName
	if clientName == "" {
		clientName = grant.ClientID
	}

	// Resource display name
	resourceName := grant.ResourceDisplayName
	if resourceName == "" {
		resourceName = grant.ResourceID
	}

	// Thread-safe append
	m.mu.Lock()
	m.GrantRows = append(m.GrantRows, []string{
		m.TenantName,
		m.TenantID,
		grant.ID,
		consentTypeDisplay,
		clientName,
		grant.ClientID,
		resourceName,
		grant.ResourceID,
		scopesDisplay,
		riskyIndicator,
		riskyPermsDisplay,
		externalIndicator,
		principalDisplay,
		grant.PrincipalID,
		grant.StartTime,
		grant.ExpiryTime,
	})
	m.mu.Unlock()
}

// ------------------------------
// Write output
// ------------------------------
func (m *ConsentGrantsModule) writeOutput(logger internal.Logger) {
	if len(m.GrantRows) == 0 {
		logger.InfoM("No OAuth2 consent grants found", globals.AZ_CONSENT_GRANTS_MODULE_NAME)
		return
	}

	// Define headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Grant ID",
		"Consent Type",
		"Client Application",
		"Client ID",
		"Resource (API)",
		"Resource ID",
		"Permissions/Scopes",
		"Risk Level",
		"Risky Permissions",
		"External App",
		"Granted By (User)",
		"Principal ID",
		"Start Time",
		"Expiry Time",
	}

	// Generate loot files
	lootFiles := m.generateConsentGrantsLootFiles()

	// Build output
	output := ConsentGrantsOutput{
		Table: []internal.TableFile{
			{
				Header:    headers,
				Body:      m.GrantRows,
				TableCols: headers,
				Name:      "consent-grants",
			},
		},
		Loot: lootFiles,
	}

	// Write table
	// TODO: Implement proper output writing
	/*
	if err := internal.WriteFullOutput(
		output,
		m.OutputDirectory,
		m.Verbosity,
		globals.AZ_CONSENT_GRANTS_MODULE_NAME,
		m.AWSProfile,
		m.TenantID,
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_CONSENT_GRANTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
	*/
	_ = output // Use variable to avoid unused warning

	// Count stats for summary
	adminConsentCount := 0
	userConsentCount := 0
	riskyCount := 0
	externalCount := 0

	for _, row := range m.GrantRows {
		if strings.Contains(row[3], "Admin") {
			adminConsentCount++
		} else if strings.Contains(row[3], "User") {
			userConsentCount++
		}

		if strings.Contains(row[9], "RISKY") {
			riskyCount++
		}

		if strings.Contains(row[11], "External") {
			externalCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d OAuth2 Consent Grants for tenant: %s (Admin: %d, User: %d, Risky: %d, External: %d)",
		len(m.GrantRows), m.TenantName, adminConsentCount, userConsentCount, riskyCount, externalCount), globals.AZ_CONSENT_GRANTS_MODULE_NAME)
}

// ======================
// Loot File Generation
// ======================

// generateConsentGrantsLootFiles creates actionable loot files from consent grants data
func (m *ConsentGrantsModule) generateConsentGrantsLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile

	// 1. Risky consent grants (high-privilege permissions)
	if riskyLoot := m.generateRiskyConsentGrantsLoot(); riskyLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "consent-grants-risky",
			Contents: riskyLoot,
		})
	}

	// 2. External/multi-tenant applications with access
	if externalLoot := m.generateExternalAppsLoot(); externalLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "consent-grants-external-apps",
			Contents: externalLoot,
		})
	}

	// 3. User consent grants (non-admin)
	if userConsentLoot := m.generateUserConsentLoot(); userConsentLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "consent-grants-user-consent",
			Contents: userConsentLoot,
		})
	}

	// 4. Remediation commands
	if remediationLoot := m.generateRemediationCommandsLoot(); remediationLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "consent-grants-remediation",
			Contents: remediationLoot,
		})
	}

	return lootFiles
}

// generateRiskyConsentGrantsLoot identifies OAuth2 grants with dangerous permissions
func (m *ConsentGrantsModule) generateRiskyConsentGrantsLoot() string {
	type RiskyGrant struct {
		TenantName          string
		TenantID            string
		GrantID             string
		ConsentType         string
		ClientApp           string
		ClientID            string
		Resource            string
		ResourceID          string
		RiskyPermissions    string
		GrantedBy           string
		PrincipalID         string
		IsExternal          bool
	}

	var riskyGrants []RiskyGrant

	// Scan for risky grants (row[9] contains "RISKY")
	for _, row := range m.GrantRows {
		if len(row) < 16 {
			continue
		}

		riskLevel := row[9]
		if !strings.Contains(riskLevel, "RISKY") {
			continue
		}

		riskyGrants = append(riskyGrants, RiskyGrant{
			TenantName:       row[0],
			TenantID:         row[1],
			GrantID:          row[2],
			ConsentType:      row[3],
			ClientApp:        row[4],
			ClientID:         row[5],
			Resource:         row[6],
			ResourceID:       row[7],
			RiskyPermissions: row[10],
			GrantedBy:        row[12],
			PrincipalID:      row[13],
			IsExternal:       strings.Contains(row[11], "External"),
		})
	}

	if len(riskyGrants) == 0 {
		return ""
	}

	var loot strings.Builder
	loot.WriteString("# Risky OAuth2 Consent Grants\n\n")
	loot.WriteString(fmt.Sprintf("Found %d OAuth2 consent grants with risky/high-privilege permissions.\n", len(riskyGrants)))
	loot.WriteString("These grants could be abused for data exfiltration, privilege escalation, or persistence.\n\n")

	loot.WriteString("## High-Risk Consent Grants\n\n")
	for i, grant := range riskyGrants {
		loot.WriteString(fmt.Sprintf("### %d. %s\n", i+1, grant.ClientApp))
		loot.WriteString(fmt.Sprintf("- **Client ID**: %s\n", grant.ClientID))
		loot.WriteString(fmt.Sprintf("- **Resource/API**: %s\n", grant.Resource))
		loot.WriteString(fmt.Sprintf("- **Consent Type**: %s\n", grant.ConsentType))

		if grant.IsExternal {
			loot.WriteString("- **⚠ EXTERNAL/MULTI-TENANT APPLICATION** - Increased risk of data exfiltration\n")
		}

		loot.WriteString(fmt.Sprintf("- **Risky Permissions**: %s\n", grant.RiskyPermissions))

		if strings.Contains(grant.ConsentType, "User") {
			loot.WriteString(fmt.Sprintf("- **Granted By**: %s (User Consent)\n", grant.GrantedBy))
		} else {
			loot.WriteString("- **Granted By**: Admin Consent (applies to all users)\n")
		}

		loot.WriteString("\n**Risk Analysis**:\n")
		permissions := strings.Split(grant.RiskyPermissions, "; ")
		for _, perm := range permissions {
			loot.WriteString(fmt.Sprintf("- `%s`: %s\n", perm, explainPermissionRisk(perm)))
		}

		loot.WriteString("\n**Investigation Commands**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString(fmt.Sprintf("# Get details about this application\naz ad sp show --id %s --output json\n\n", grant.ClientID))
		loot.WriteString(fmt.Sprintf("# Get all consent grants for this app\naz rest --method GET --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '%s'\"\n\n", grant.ClientID))
		loot.WriteString(fmt.Sprintf("# Revoke this specific grant (if needed)\naz rest --method DELETE --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/%s\"\n", grant.GrantID))
		loot.WriteString("```\n\n")
	}

	loot.WriteString("## Recommended Actions\n\n")
	loot.WriteString("1. **Review each risky grant** - Determine if the permissions are necessary for business operations\n")
	loot.WriteString("2. **Audit external apps** - External/multi-tenant apps pose higher risk for data exfiltration\n")
	loot.WriteString("3. **Check user consent grants** - User-granted consents bypass admin controls\n")
	loot.WriteString("4. **Enable Conditional Access** - Use app control policies to restrict risky permissions\n")
	loot.WriteString("5. **Revoke unnecessary grants** - Remove grants that are no longer needed\n")
	loot.WriteString("6. **Implement consent policies** - Configure admin consent requirements for risky permissions\n\n")

	return loot.String()
}

// generateExternalAppsLoot identifies external/multi-tenant applications with access
func (m *ConsentGrantsModule) generateExternalAppsLoot() string {
	type ExternalApp struct {
		ClientApp        string
		ClientID         string
		Resource         string
		Permissions      string
		RiskyPermissions string
		ConsentType      string
		GrantedBy        string
	}

	externalAppsMap := make(map[string]*ExternalApp)

	// Find all external apps
	for _, row := range m.GrantRows {
		if len(row) < 16 {
			continue
		}

		externalIndicator := row[11]
		if !strings.Contains(externalIndicator, "External") {
			continue
		}

		clientID := row[5]
		if _, exists := externalAppsMap[clientID]; !exists {
			externalAppsMap[clientID] = &ExternalApp{
				ClientApp:        row[4],
				ClientID:         clientID,
				Resource:         row[6],
				Permissions:      row[8],
				RiskyPermissions: row[10],
				ConsentType:      row[3],
				GrantedBy:        row[12],
			}
		}
	}

	if len(externalAppsMap) == 0 {
		return ""
	}

	var loot strings.Builder
	loot.WriteString("# External/Multi-Tenant Applications with Access\n\n")
	loot.WriteString(fmt.Sprintf("Found %d external or multi-tenant applications with consent grants in your tenant.\n", len(externalAppsMap)))
	loot.WriteString("External apps pose increased risk for data exfiltration as they run outside your organization's control.\n\n")

	loot.WriteString("## External Applications\n\n")
	for _, app := range externalAppsMap {
		loot.WriteString(fmt.Sprintf("### %s\n", app.ClientApp))
		loot.WriteString(fmt.Sprintf("- **Client ID**: %s\n", app.ClientID))
		loot.WriteString(fmt.Sprintf("- **Resource/API**: %s\n", app.Resource))
		loot.WriteString(fmt.Sprintf("- **Permissions**: %s\n", app.Permissions))
		loot.WriteString(fmt.Sprintf("- **Consent Type**: %s\n", app.ConsentType))

		if app.RiskyPermissions != "None" && app.RiskyPermissions != "" {
			loot.WriteString(fmt.Sprintf("- **⚠ Risky Permissions**: %s\n", app.RiskyPermissions))
		}

		if strings.Contains(app.ConsentType, "User") {
			loot.WriteString(fmt.Sprintf("- **Granted By**: %s\n", app.GrantedBy))
		}

		loot.WriteString("\n**Investigation Commands**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString(fmt.Sprintf("# Get service principal details\naz ad sp show --id %s --output json\n\n", app.ClientID))
		loot.WriteString(fmt.Sprintf("# Check app owner/publisher\naz ad app show --id %s --query \"{displayName:displayName, publisherDomain:publisherDomain, verifiedPublisher:verifiedPublisher}\"\n\n", app.ClientID))
		loot.WriteString("# List all users who have signed into this app\n")
		loot.WriteString(fmt.Sprintf("az rest --method GET --url \"https://graph.microsoft.com/v1.0/servicePrincipals(appId='%s')/oauth2PermissionGrants\"\n", app.ClientID))
		loot.WriteString("```\n\n")
	}

	loot.WriteString("## Risk Mitigation\n\n")
	loot.WriteString("**External App Security Best Practices**:\n")
	loot.WriteString("1. **Verify Publisher** - Check if the app has a verified publisher badge\n")
	loot.WriteString("2. **Review Permissions** - Ensure permissions are appropriate for the app's function\n")
	loot.WriteString("3. **Check Privacy Policy** - Understand how the vendor handles your data\n")
	loot.WriteString("4. **Implement App Governance** - Use Microsoft Defender for Cloud Apps to monitor external app behavior\n")
	loot.WriteString("5. **Disable User Consent** - Require admin approval for all external app consents\n")
	loot.WriteString("6. **Regular Audits** - Periodically review and revoke access for unused external apps\n\n")

	loot.WriteString("**Commands to Block User Consent for External Apps**:\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# Disable user consent for unverified publishers\n")
	loot.WriteString("az rest --method PATCH \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/policies/authorizationPolicy\" \\\n")
	loot.WriteString("  --body '{\"defaultUserRolePermissions\": {\"permissionGrantPoliciesAssigned\": [\"ManagePermissionGrantsForSelf.microsoft-user-default-low\"]}}'\n")
	loot.WriteString("```\n\n")

	return loot.String()
}

// generateUserConsentLoot identifies non-admin user consent grants
func (m *ConsentGrantsModule) generateUserConsentLoot() string {
	type UserConsentGrant struct {
		GrantID          string
		GrantedBy        string
		PrincipalID      string
		ClientApp        string
		ClientID         string
		Permissions      string
		RiskyPermissions string
		IsExternal       bool
	}

	var userGrants []UserConsentGrant

	// Find all user consent grants (row[3] contains "User")
	for _, row := range m.GrantRows {
		if len(row) < 16 {
			continue
		}

		consentType := row[3]
		if !strings.Contains(consentType, "User") {
			continue
		}

		userGrants = append(userGrants, UserConsentGrant{
			GrantID:          row[2],
			GrantedBy:        row[12],
			PrincipalID:      row[13],
			ClientApp:        row[4],
			ClientID:         row[5],
			Permissions:      row[8],
			RiskyPermissions: row[10],
			IsExternal:       strings.Contains(row[11], "External"),
		})
	}

	if len(userGrants) == 0 {
		return ""
	}

	var loot strings.Builder
	loot.WriteString("# User Consent Grants (Non-Admin)\n\n")
	loot.WriteString(fmt.Sprintf("Found %d user-level consent grants where individual users granted access to applications.\n", len(userGrants)))
	loot.WriteString("User consent grants can bypass admin controls and introduce shadow IT risks.\n\n")

	// Group by user
	userGrantsMap := make(map[string][]UserConsentGrant)
	for _, grant := range userGrants {
		userGrantsMap[grant.GrantedBy] = append(userGrantsMap[grant.GrantedBy], grant)
	}

	loot.WriteString("## Users Who Granted Consent\n\n")
	for user, grants := range userGrantsMap {
		loot.WriteString(fmt.Sprintf("### %s\n", user))
		loot.WriteString(fmt.Sprintf("Granted consent to %d application(s):\n\n", len(grants)))

		for _, grant := range grants {
			loot.WriteString(fmt.Sprintf("#### %s\n", grant.ClientApp))
			loot.WriteString(fmt.Sprintf("- **Client ID**: %s\n", grant.ClientID))
			loot.WriteString(fmt.Sprintf("- **Permissions**: %s\n", grant.Permissions))

			if grant.IsExternal {
				loot.WriteString("- **⚠ External/Multi-Tenant App**\n")
			}

			if grant.RiskyPermissions != "None" && grant.RiskyPermissions != "" {
				loot.WriteString(fmt.Sprintf("- **⚠ Risky Permissions**: %s\n", grant.RiskyPermissions))
			}

			loot.WriteString(fmt.Sprintf("- **Grant ID**: %s\n", grant.GrantID))
			loot.WriteString("\n")
		}

		loot.WriteString("**Investigation Commands**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString(fmt.Sprintf("# Get user details\naz ad user show --id %s\n\n", grants[0].PrincipalID))
		loot.WriteString(fmt.Sprintf("# List all OAuth2 grants for this user\naz rest --method GET --url \"https://graph.microsoft.com/v1.0/users/%s/oauth2PermissionGrants\"\n", grants[0].PrincipalID))
		loot.WriteString("```\n\n")
	}

	loot.WriteString("## Remediation Actions\n\n")
	loot.WriteString("**Revoke User Consent Grants** (if policy violation detected):\n")
	loot.WriteString("```bash\n")
	for _, grant := range userGrants {
		if grant.RiskyPermissions != "None" && grant.RiskyPermissions != "" {
			loot.WriteString(fmt.Sprintf("# Revoke risky grant for %s (%s)\n", grant.GrantedBy, grant.ClientApp))
			loot.WriteString(fmt.Sprintf("az rest --method DELETE --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/%s\"\n\n", grant.GrantID))
		}
	}
	loot.WriteString("```\n\n")

	loot.WriteString("**Configure User Consent Settings**:\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# Disable user consent entirely (require admin approval)\n")
	loot.WriteString("az rest --method PATCH \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/policies/authorizationPolicy\" \\\n")
	loot.WriteString("  --body '{\"defaultUserRolePermissions\": {\"permissionGrantPoliciesAssigned\": []}}'\n\n")
	loot.WriteString("# Allow user consent only for low-risk permissions from verified publishers\n")
	loot.WriteString("az rest --method PATCH \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/policies/authorizationPolicy\" \\\n")
	loot.WriteString("  --body '{\"defaultUserRolePermissions\": {\"permissionGrantPoliciesAssigned\": [\"ManagePermissionGrantsForSelf.microsoft-user-default-low\"]}}'\n")
	loot.WriteString("```\n\n")

	return loot.String()
}

// generateRemediationCommandsLoot provides commands for investigating and revoking grants
func (m *ConsentGrantsModule) generateRemediationCommandsLoot() string {
	var loot strings.Builder
	loot.WriteString("# OAuth2 Consent Grant Remediation Commands\n\n")
	loot.WriteString("Use these commands to investigate, audit, and remediate OAuth2 consent grants.\n\n")

	loot.WriteString("## General Investigation Commands\n\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# List all OAuth2 permission grants in tenant\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants\" --output table\n\n")
	loot.WriteString("# List all service principals (apps) with permissions\n")
	loot.WriteString("az ad sp list --all --query \"[].{DisplayName:displayName, AppId:appId, PublisherName:publisherName}\" --output table\n\n")
	loot.WriteString("# Check user consent settings\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/policies/authorizationPolicy\" --query \"defaultUserRolePermissions\"\n\n")
	loot.WriteString("# List all apps with admin consent\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'\" --output table\n")
	loot.WriteString("```\n\n")

	// Find unique client IDs for targeted remediation
	clientIDs := make(map[string]string) // clientID -> clientName
	grantIDs := []string{}

	for _, row := range m.GrantRows {
		if len(row) >= 16 {
			// Collect risky grant IDs
			if strings.Contains(row[9], "RISKY") {
				grantIDs = append(grantIDs, row[2])
			}
			// Collect client IDs
			clientIDs[row[5]] = row[4]
		}
	}

	if len(grantIDs) > 0 {
		loot.WriteString("## Revoke Risky Consent Grants\n\n")
		loot.WriteString("**WARNING**: Review each grant before revoking. Revoking may break legitimate business applications.\n\n")
		loot.WriteString("```bash\n")
		for i, grantID := range grantIDs {
			if i >= 10 { // Limit to first 10 for readability
				loot.WriteString(fmt.Sprintf("# ... and %d more risky grants (see main output file)\n", len(grantIDs)-10))
				break
			}
			loot.WriteString(fmt.Sprintf("# Revoke risky grant %d\n", i+1))
			loot.WriteString(fmt.Sprintf("az rest --method DELETE --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/%s\"\n\n", grantID))
		}
		loot.WriteString("```\n\n")
	}

	if len(clientIDs) > 0 {
		loot.WriteString("## Investigate Specific Applications\n\n")
		loot.WriteString("```bash\n")
		count := 0
		for clientID, clientName := range clientIDs {
			if count >= 5 { // Limit to first 5
				loot.WriteString(fmt.Sprintf("# ... and %d more applications\n", len(clientIDs)-5))
				break
			}
			loot.WriteString(fmt.Sprintf("# Investigate: %s\n", clientName))
			loot.WriteString(fmt.Sprintf("az ad sp show --id %s --output json\n", clientID))
			loot.WriteString(fmt.Sprintf("az rest --method GET --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '%s'\"\n\n", clientID))
			count++
		}
		loot.WriteString("```\n\n")
	}

	loot.WriteString("## Configure Consent Policies\n\n")
	loot.WriteString("**Option 1: Disable All User Consent (Most Secure)**\n")
	loot.WriteString("```bash\n")
	loot.WriteString("az rest --method PATCH \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/policies/authorizationPolicy\" \\\n")
	loot.WriteString("  --body '{\"defaultUserRolePermissions\": {\"permissionGrantPoliciesAssigned\": []}}'\n")
	loot.WriteString("```\n\n")

	loot.WriteString("**Option 2: Allow User Consent for Low-Risk, Verified Publishers**\n")
	loot.WriteString("```bash\n")
	loot.WriteString("az rest --method PATCH \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/policies/authorizationPolicy\" \\\n")
	loot.WriteString("  --body '{\"defaultUserRolePermissions\": {\"permissionGrantPoliciesAssigned\": [\"ManagePermissionGrantsForSelf.microsoft-user-default-low\"]}}'\n")
	loot.WriteString("```\n\n")

	loot.WriteString("**Option 3: Create Custom Consent Policy**\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# Create custom permission grant policy\n")
	loot.WriteString("az rest --method POST \\\n")
	loot.WriteString("  --url \"https://graph.microsoft.com/v1.0/policies/permissionGrantPolicies\" \\\n")
	loot.WriteString("  --body '{\n")
	loot.WriteString("    \"id\": \"custom-consent-policy\",\n")
	loot.WriteString("    \"displayName\": \"Custom User Consent Policy\",\n")
	loot.WriteString("    \"description\": \"Allow user consent only for verified publishers with low-risk permissions\"\n")
	loot.WriteString("  }'\n")
	loot.WriteString("```\n\n")

	loot.WriteString("## Monitoring and Auditing\n\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# Monitor for new consent grants (check audit logs)\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDisplayName eq 'Consent to application'\" --output table\n\n")
	loot.WriteString("# Export all consent grants for compliance review\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants\" --output json > consent-grants-export.json\n\n")
	loot.WriteString("# Find apps with specific high-risk permissions\n")
	loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=scope eq 'Mail.ReadWrite'\" --output table\n")
	loot.WriteString("```\n\n")

	return loot.String()
}

// explainPermissionRisk provides a description of why a permission is risky
func explainPermissionRisk(permission string) string {
	riskDescriptions := map[string]string{
		"Mail.ReadWrite":                   "Can read, modify, and send emails on behalf of users - data exfiltration risk",
		"Mail.ReadWrite.All":               "Can access all mailboxes in the organization - mass data exfiltration",
		"Mail.Send":                        "Can send emails on behalf of users - phishing/impersonation risk",
		"Files.ReadWrite.All":              "Can access all files in OneDrive and SharePoint - data exfiltration",
		"Directory.ReadWrite.All":          "Can modify directory including users, groups, apps - full tenant compromise",
		"User.ReadWrite.All":               "Can create, modify, and delete users - account takeover",
		"Application.ReadWrite.All":        "Can register and modify applications - backdoor creation",
		"RoleManagement.ReadWrite.Directory": "Can assign directory roles including Global Admin - privilege escalation",
		"AppRoleAssignment.ReadWrite.All":  "Can grant app permissions - privilege escalation",
		"Group.ReadWrite.All":              "Can modify group memberships - privilege escalation",
		"Sites.FullControl.All":            "Full control over all SharePoint sites - data manipulation",
		"Calendars.ReadWrite":              "Can read and modify calendars - information disclosure",
		"Contacts.ReadWrite":               "Can read and modify contacts - information disclosure",
		"Notes.ReadWrite.All":              "Can access all OneNote notebooks - data exfiltration",
		"Tasks.ReadWrite":                  "Can read and modify tasks - information disclosure",
		"IdentityRiskEvent.ReadWrite.All":  "Can modify risk events - security bypass",
		"SecurityEvents.ReadWrite.All":     "Can modify security events - security bypass",
		"ThreatIndicators.ReadWrite.OwnedBy": "Can create threat indicators - false positive attacks",
	}

	// Try exact match first
	if desc, exists := riskDescriptions[permission]; exists {
		return desc
	}

	// Try partial matches
	for pattern, desc := range riskDescriptions {
		if strings.Contains(permission, pattern) || strings.Contains(pattern, permission) {
			return desc
		}
	}

	// Generic risk descriptions based on permission type
	lower := strings.ToLower(permission)
	if strings.Contains(lower, "readwrite.all") {
		return "Organization-wide read/write access - high risk for data manipulation"
	} else if strings.Contains(lower, "readwrite") {
		return "Read and write access - potential for data exfiltration and modification"
	} else if strings.Contains(lower, ".all") {
		return "Broad scope permission - access beyond user's own data"
	} else if strings.Contains(lower, "write") {
		return "Write access - can modify data"
	}

	return "Review permission scope and necessity"
}
