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
		Loot: []internal.LootFile{},
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
