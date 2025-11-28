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
var AzIdentityProtectionCommand = &cobra.Command{
	Use:     "identity-protection",
	Aliases: []string{"idp", "risky-users"},
	Short:   "Enumerate Azure AD Identity Protection - risky users, sign-ins, and detections",
	Long: `
Enumerate Azure AD Identity Protection for a specific tenant:
  ./cloudfox az identity-protection --tenant TENANT_ID

FEATURES:
  - Risky users with risk level and state
  - Risky sign-ins with risk details
  - Risk detections with activity types
  - Risk policies (user and sign-in risk policies)
  - Compromised credentials analysis

REQUIREMENTS:
  - Azure AD Premium P2 license
  - Microsoft Graph permissions: IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All

NOTE: This module requires Azure AD Identity Protection to be enabled in the tenant.`,
	Run: ListIdentityProtection,
}

// ------------------------------
// Module struct
// ------------------------------
type IdentityProtectionModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	RiskyUserRows     [][]string
	RiskySignInRows   [][]string
	RiskDetectionRows [][]string
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type IdentityProtectionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o IdentityProtectionOutput) TableFiles() []internal.TableFile { return o.Table }
func (o IdentityProtectionOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListIdentityProtection(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &IdentityProtectionModule{
		BaseAzureModule:   azinternal.NewBaseAzureModule(cmdCtx, 5),
		RiskyUserRows:     [][]string{},
		RiskySignInRows:   [][]string{},
		RiskDetectionRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"identity-protection-commands":      {Name: "identity-protection-commands", Contents: ""},
			"risky-users":                       {Name: "risky-users", Contents: "# Risky Users\n\n"},
			"compromised-credentials":           {Name: "compromised-credentials", Contents: "# Compromised Credentials\n\n"},
			"identity-protection-remediation":   {Name: "identity-protection-remediation", Contents: "# Identity Protection Remediation\n\n"},
			"identity-protection-investigation": {Name: "identity-protection-investigation", Contents: "# Identity Protection Investigation\n\n"},
		},
	}

	module.PrintIdentityProtection(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *IdentityProtectionModule) PrintIdentityProtection(ctx context.Context, logger internal.Logger) {
	// This is a tenant-level module
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.enumerateTenant(ctx, logger)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.enumerateTenant(ctx, logger)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Enumerate tenant
// ------------------------------
func (m *IdentityProtectionModule) enumerateTenant(ctx context.Context, logger internal.Logger) {
	// Enumerate risky users
	m.enumerateRiskyUsers(ctx, logger)

	// Enumerate risky sign-ins
	m.enumerateRiskySignIns(ctx, logger)

	// Enumerate risk detections
	m.enumerateRiskDetections(ctx, logger)
}

// ------------------------------
// Enumerate risky users
// ------------------------------
func (m *IdentityProtectionModule) enumerateRiskyUsers(ctx context.Context, logger internal.Logger) {
	graphClient, err := azinternal.GetGraphServiceClient(m.Session)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Graph client: %v", err), globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Get risky users using Graph API
	riskyUsers, err := graphClient.IdentityProtection().RiskyUsers().Get(ctx, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate risky users: %v. Ensure you have IdentityRiskyUser.Read.All permission and Azure AD Premium P2 license.", err), globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	if riskyUsers == nil || riskyUsers.GetValue() == nil {
		logger.InfoM("No risky users found", globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		return
	}

	for _, user := range riskyUsers.GetValue() {
		if user == nil {
			continue
		}

		userPrincipalName := azinternal.SafeStringPtr(user.GetUserPrincipalName())
		userDisplayName := azinternal.SafeStringPtr(user.GetUserDisplayName())
		userID := azinternal.SafeStringPtr(user.GetId())
		riskLevel := "Unknown"
		if user.GetRiskLevel() != nil {
			riskLevel = string(*user.GetRiskLevel())
		}
		riskState := "Unknown"
		if user.GetRiskState() != nil {
			riskState = string(*user.GetRiskState())
		}
		riskDetail := "Unknown"
		if user.GetRiskDetail() != nil {
			riskDetail = string(*user.GetRiskDetail())
		}
		lastUpdated := "N/A"
		if user.GetRiskLastUpdatedDateTime() != nil {
			lastUpdated = user.GetRiskLastUpdatedDateTime().String()
		}

		risk := "INFO"
		if strings.ToLower(riskLevel) == "high" {
			risk = "HIGH"
		} else if strings.ToLower(riskLevel) == "medium" {
			risk = "MEDIUM"
		}

		row := []string{
			m.TenantName,
			m.TenantID,
			userPrincipalName,
			userDisplayName,
			userID,
			riskLevel,
			riskState,
			riskDetail,
			lastUpdated,
			risk,
		}

		m.mu.Lock()
		m.RiskyUserRows = append(m.RiskyUserRows, row)
		m.mu.Unlock()
		m.CommandCounter.Total++

		// Add to loot
		if risk == "HIGH" || risk == "MEDIUM" {
			m.addRiskyUserLoot(userPrincipalName, userDisplayName, userID, riskLevel, riskState, riskDetail, lastUpdated)
		}
	}
}

// ------------------------------
// Enumerate risky sign-ins
// ------------------------------
func (m *IdentityProtectionModule) enumerateRiskySignIns(ctx context.Context, logger internal.Logger) {
	graphClient, err := azinternal.GetGraphServiceClient(m.Session)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Graph client: %v", err), globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Get risky sign-ins using Graph API
	riskySignIns, err := graphClient.IdentityProtection().RiskyServicePrincipals().Get(ctx, nil)
	if err != nil {
		// Try alternative endpoint for sign-ins
		logger.InfoM("Could not enumerate risky service principals, this may be expected if none exist", globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
	}

	if riskySignIns != nil && riskySignIns.GetValue() != nil {
		for _, sp := range riskySignIns.GetValue() {
			if sp == nil {
				continue
			}

			spDisplayName := azinternal.SafeStringPtr(sp.GetDisplayName())
			spID := azinternal.SafeStringPtr(sp.GetId())
			appID := azinternal.SafeStringPtr(sp.GetAppId())
			riskLevel := "Unknown"
			if sp.GetRiskLevel() != nil {
				riskLevel = string(*sp.GetRiskLevel())
			}
			riskState := "Unknown"
			if sp.GetRiskState() != nil {
				riskState = string(*sp.GetRiskState())
			}

			risk := "INFO"
			if strings.ToLower(riskLevel) == "high" {
				risk = "HIGH"
			} else if strings.ToLower(riskLevel) == "medium" {
				risk = "MEDIUM"
			}

			row := []string{
				m.TenantName,
				m.TenantID,
				spDisplayName,
				appID,
				spID,
				riskLevel,
				riskState,
				risk,
			}

			m.mu.Lock()
			m.RiskySignInRows = append(m.RiskySignInRows, row)
			m.mu.Unlock()
			m.CommandCounter.Total++
		}
	}
}

// ------------------------------
// Enumerate risk detections
// ------------------------------
func (m *IdentityProtectionModule) enumerateRiskDetections(ctx context.Context, logger internal.Logger) {
	graphClient, err := azinternal.GetGraphServiceClient(m.Session)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Graph client: %v", err), globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Get risk detections using Graph API
	riskDetections, err := graphClient.IdentityProtection().RiskDetections().Get(ctx, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate risk detections: %v. Ensure you have IdentityRiskEvent.Read.All permission.", err), globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	if riskDetections == nil || riskDetections.GetValue() == nil {
		logger.InfoM("No risk detections found", globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		return
	}

	for _, detection := range riskDetections.GetValue() {
		if detection == nil {
			continue
		}

		detectionID := azinternal.SafeStringPtr(detection.GetId())
		userPrincipalName := azinternal.SafeStringPtr(detection.GetUserPrincipalName())
		userDisplayName := azinternal.SafeStringPtr(detection.GetUserDisplayName())
		riskType := "Unknown"
		if detection.GetRiskEventType() != nil {
			riskType = *detection.GetRiskEventType()
		}
		riskLevel := "Unknown"
		if detection.GetRiskLevel() != nil {
			riskLevel = string(*detection.GetRiskLevel())
		}
		riskState := "Unknown"
		if detection.GetRiskState() != nil {
			riskState = string(*detection.GetRiskState())
		}
		detectedDateTime := "N/A"
		if detection.GetDetectedDateTime() != nil {
			detectedDateTime = detection.GetDetectedDateTime().String()
		}
		activity := "Unknown"
		if detection.GetActivity() != nil {
			activity = string(*detection.GetActivity())
		}
		ipAddress := azinternal.SafeStringPtr(detection.GetIpAddress())
		location := "Unknown"
		if detection.GetLocation() != nil {
			city := azinternal.SafeStringPtr(detection.GetLocation().GetCity())
			country := azinternal.SafeStringPtr(detection.GetLocation().GetCountryOrRegion())
			location = fmt.Sprintf("%s, %s", city, country)
		}

		risk := "INFO"
		if strings.ToLower(riskLevel) == "high" {
			risk = "HIGH"
		} else if strings.ToLower(riskLevel) == "medium" {
			risk = "MEDIUM"
		}

		row := []string{
			m.TenantName,
			m.TenantID,
			detectionID,
			userPrincipalName,
			userDisplayName,
			riskType,
			riskLevel,
			riskState,
			activity,
			ipAddress,
			location,
			detectedDateTime,
			risk,
		}

		m.mu.Lock()
		m.RiskDetectionRows = append(m.RiskDetectionRows, row)
		m.mu.Unlock()
		m.CommandCounter.Total++
	}
}

// ------------------------------
// Add risky user loot
// ------------------------------
func (m *IdentityProtectionModule) addRiskyUserLoot(upn, displayName, userID, riskLevel, riskState, riskDetail, lastUpdated string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["risky-users"].Contents += fmt.Sprintf(
		"## Risky User: %s (%s)\n"+
			"User Principal Name: %s\n"+
			"User ID: %s\n"+
			"Risk Level: %s\n"+
			"Risk State: %s\n"+
			"Risk Detail: %s\n"+
			"Last Updated: %s\n\n",
		displayName, upn,
		upn,
		userID,
		riskLevel,
		riskState,
		riskDetail,
		lastUpdated,
	)

	if strings.Contains(strings.ToLower(riskDetail), "leaked") || strings.Contains(strings.ToLower(riskState), "atRisk") {
		m.LootMap["compromised-credentials"].Contents += fmt.Sprintf(
			"## COMPROMISED: %s (%s)\n"+
				"User ID: %s\n"+
				"Risk Level: %s\n"+
				"Risk Detail: %s\n"+
				"IMMEDIATE ACTION REQUIRED: Reset password and revoke sessions\n\n",
			displayName, upn,
			userID,
			riskLevel,
			riskDetail,
		)
	}

	m.LootMap["identity-protection-commands"].Contents += fmt.Sprintf(
		"## Risky User: %s\n"+
			"# Confirm user compromised\n"+
			"az rest --method POST --uri \"https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised\" \\\n"+
			"  --body '{\"userIds\": [\"%s\"]}'\n\n"+
			"# Dismiss user risk\n"+
			"az rest --method POST --uri \"https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss\" \\\n"+
			"  --body '{\"userIds\": [\"%s\"]}'\n\n"+
			"# Get user risk history\n"+
			"az rest --method GET --uri \"https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/%s/history\"\n\n"+
			"# Force password reset\n"+
			"az ad user update --id %s --force-change-password-next-sign-in true\n\n"+
			"# Revoke user sessions\n"+
			"az ad user revoke-sessions --id %s\n\n",
		upn,
		userID,
		userID,
		userID,
		userID,
		userID,
	)

	m.LootMap["identity-protection-remediation"].Contents += fmt.Sprintf(
		"## Remediation for: %s (%s)\n"+
			"Risk Level: %s | Risk State: %s\n\n"+
			"### Immediate Actions:\n"+
			"1. Confirm if user is compromised (check with user)\n"+
			"2. If compromised:\n"+
			"   - Force password reset: az ad user update --id %s --force-change-password-next-sign-in true\n"+
			"   - Revoke all sessions: az ad user revoke-sessions --id %s\n"+
			"   - Review recent sign-in activity and audit logs\n"+
			"   - Check for any suspicious activity or data access\n"+
			"3. If false positive:\n"+
			"   - Dismiss the risk in Identity Protection\n"+
			"   - Document the reason for dismissal\n\n"+
			"### Investigation Steps:\n"+
			"1. Review sign-in logs: az ad user list-sign-ins --id %s\n"+
			"2. Check for unusual locations or IP addresses\n"+
			"3. Review recent changes to user permissions\n"+
			"4. Check for MFA bypass attempts\n"+
			"5. Review audit logs for the user\n\n",
		displayName, upn,
		riskLevel, riskState,
		userID,
		userID,
		userID,
	)

	m.LootMap["identity-protection-investigation"].Contents += fmt.Sprintf(
		"## Investigation: %s (%s)\n"+
			"### User Details\n"+
			"User ID: %s\n"+
			"Risk Level: %s\n"+
			"Risk State: %s\n"+
			"Risk Detail: %s\n"+
			"Last Updated: %s\n\n"+
			"### Investigation Commands\n"+
			"# Get user details\n"+
			"az ad user show --id %s\n\n"+
			"# Get user's group memberships\n"+
			"az ad user get-member-groups --id %s\n\n"+
			"# Get user's assigned roles\n"+
			"az rest --method GET --uri \"https://graph.microsoft.com/v1.0/users/%s/appRoleAssignments\"\n\n"+
			"# Get user's devices\n"+
			"az rest --method GET --uri \"https://graph.microsoft.com/v1.0/users/%s/registeredDevices\"\n\n"+
			"# Get user's recent sign-ins (requires Azure AD Premium)\n"+
			"az rest --method GET --uri \"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userId eq '%s'\"\n\n",
		displayName, upn,
		userID,
		riskLevel,
		riskState,
		riskDetail,
		lastUpdated,
		userID,
		userID,
		userID,
		userID,
		userID,
	)
}

// ------------------------------
// Write output
// ------------------------------
func (m *IdentityProtectionModule) writeOutput(ctx context.Context, logger internal.Logger) {
	totalFindings := len(m.RiskyUserRows) + len(m.RiskySignInRows) + len(m.RiskDetectionRows)
	if totalFindings == 0 {
		logger.InfoM("No Identity Protection findings. This could mean: (1) No risky users/sign-ins detected, (2) Identity Protection not enabled, or (3) Missing permissions", globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		return
	}

	tables := []internal.TableFile{}

	// Add risky users table
	if len(m.RiskyUserRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "risky-users",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"User Principal Name",
				"Display Name",
				"User ID",
				"Risk Level",
				"Risk State",
				"Risk Detail",
				"Last Updated",
				"Risk",
			},
			Body: m.RiskyUserRows,
		})
	}

	// Add risky sign-ins table
	if len(m.RiskySignInRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "risky-service-principals",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Display Name",
				"App ID",
				"Service Principal ID",
				"Risk Level",
				"Risk State",
				"Risk",
			},
			Body: m.RiskySignInRows,
		})
	}

	// Add risk detections table
	if len(m.RiskDetectionRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "risk-detections",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Detection ID",
				"User Principal Name",
				"Display Name",
				"Risk Type",
				"Risk Level",
				"Risk State",
				"Activity",
				"IP Address",
				"Location",
				"Detected DateTime",
				"Risk",
			},
			Body: m.RiskDetectionRows,
		})
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := IdentityProtectionOutput{
		Table: tables,
		Loot:  loot,
	}

	// Write output
	if err := internal.HandleOutputSmart(
		"Azure",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"tenant",
		[]string{m.TenantID},
		[]string{m.TenantName},
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d risky users, %d risky service principals, %d risk detections",
		len(m.RiskyUserRows), len(m.RiskySignInRows), len(m.RiskDetectionRows)), globals.AZ_IDENTITY_PROTECTION_MODULE_NAME)
}
