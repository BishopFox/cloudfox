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
var AzPrincipalsCommand = &cobra.Command{
	Use:     "principals",
	Aliases: []string{"principals", "principal", "entra-principals"},
	Short:   "Enumerate Azure/Entra principals (users, service principals, managed identities)",
	Long: `
Enumerate Azure/Entra principals for a specific tenant:
./cloudfox az principals --tenant TENANT_ID

Enumerate principals for a specific subscription (tenant resolved from subscription):
./cloudfox az principals --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListPrincipals,
}

// ------------------------------
// Module struct (tenant-level enumeration)
// ------------------------------
type PrincipalsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	PrincipalRows [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Internal Principal struct
// ------------------------------
type Principal struct {
	Service     string // e.g., EntraID
	Type        string // User, ServicePrincipal, ManagedIdentity, Guest, Group, etc
	UPN         string
	DisplayName string
	PrincipalID string // Object ID GUID
	Extra       map[string]string
	// New fields for enhanced tracking
	GroupMemberships          string // Display names of groups this principal belongs to
	ConditionalAccessPolicies string // CA policies applied to this principal
}

// ------------------------------
// Output struct
// ------------------------------
type PrincipalsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrincipalsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrincipalsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListPrincipals(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_PRINCIPALS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// Test Graph API access
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		cmdCtx.Logger.InfoM("Testing Graph API access...", globals.AZ_PRINCIPALS_MODULE_NAME)
		if err := azinternal.TestGraphAPIAccess(cmdCtx.Ctx, cmdCtx.Session, cmdCtx.TenantID); err != nil {
			cmdCtx.Logger.ErrorM(fmt.Sprintf("Graph API test failed: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
			cmdCtx.Logger.InfoM("Ensure you have granted Microsoft Graph permissions: User.Read.All, Application.Read.All", globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// -------------------- Initialize module --------------------
	module := &PrincipalsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		PrincipalRows:   [][]string{},
		LootMap: map[string]*internal.LootFile{
			"principal-commands": {Name: "principal-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintPrincipals(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (tenant-level)
// ------------------------------
func (m *PrincipalsModule) PrintPrincipals(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Enumerating principals for %d tenants", len(m.Tenants)), globals.AZ_PRINCIPALS_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			// Save current context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Set tenant context
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_PRINCIPALS_MODULE_NAME)

			// Process this tenant
			m.processTenantPrincipals(ctx, logger)

			// Restore context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant mode
		logger.InfoM(fmt.Sprintf("Enumerating Principals for tenant: %s", m.TenantName), globals.AZ_PRINCIPALS_MODULE_NAME)
		m.processTenantPrincipals(ctx, logger)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// processTenantPrincipals - Process principals for a single tenant
func (m *PrincipalsModule) processTenantPrincipals(ctx context.Context, logger internal.Logger) {
	// Collect principals from multiple sources
	principals := []Principal{}

	// 1) Entra Users
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Enumerating Entra users...", globals.AZ_PRINCIPALS_MODULE_NAME)
	}
	users, uErr := azinternal.ListEntraUsers(ctx, m.Session, m.TenantID)
	if uErr == nil {
		for _, u := range users {
			// Use the actual userType from the API (e.g., "Guest", "Member")
			// Default to "User" if userType is empty or unrecognized
			uType := u.UserType
			if uType == "" {
				uType = "User"
			} else {
				// Normalize the userType for better display
				switch strings.ToLower(uType) {
				case "guest":
					uType = "Guest"
				case "member":
					uType = "User"
				default:
					// Keep whatever the API returns for other values
					uType = u.UserType
				}
			}
			principals = append(principals, Principal{
				Service:     "EntraID",
				Type:        uType,
				UPN:         azinternal.SafeString(u.UserPrincipalName),
				DisplayName: azinternal.SafeString(u.DisplayName),
				PrincipalID: azinternal.SafeString(u.ObjectID),
				Extra:       map[string]string{},
			})
		}
	} else {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list Entra users: %v", uErr), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// 2) Service Principals
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Enumerating service principals...", globals.AZ_PRINCIPALS_MODULE_NAME)
	}
	sps, spErr := azinternal.ListServicePrincipals(ctx, m.Session, m.TenantID)
	if spErr == nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Found %d service principals", len(sps)), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		for _, sp := range sps {
			principals = append(principals, Principal{
				Service:     "EntraID",
				Type:        "ServicePrincipal",
				UPN:         azinternal.SafeString(sp.AppID), // AppID stored here for display
				DisplayName: azinternal.SafeString(sp.DisplayName),
				PrincipalID: azinternal.SafeString(sp.ObjectID),
				Extra:       map[string]string{}, // No need to duplicate AppID
			})
		}
	} else {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list service principals: %v", spErr), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// 3) Security Groups
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Enumerating security groups...", globals.AZ_PRINCIPALS_MODULE_NAME)
	}
	groups, grpErr := azinternal.ListEntraGroups(ctx, m.Session, m.TenantID)
	if grpErr == nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Found %d security groups", len(groups)), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		for _, grp := range groups {
			principals = append(principals, Principal{
				Service:     "EntraID",
				Type:        "Group",
				UPN:         azinternal.SafeString(grp.UserPrincipalName),
				DisplayName: azinternal.SafeString(grp.DisplayName),
				PrincipalID: azinternal.SafeString(grp.ObjectID),
				Extra:       map[string]string{},
			})
		}
	} else {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list security groups: %v", grpErr), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// 4) User-assigned Managed Identities
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Enumerating user-assigned managed identities (per-subscription)...", globals.AZ_PRINCIPALS_MODULE_NAME)
	}
	miList := []azinternal.ManagedIdentity{}
	for _, sub := range m.Subscriptions {
		mis, miErr := azinternal.ListUserAssignedManagedIdentities(ctx, m.Session, []string{sub})
		if miErr == nil {
			miList = append(miList, mis...)
		} else {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list managed identities in subscription %s: %v", sub, miErr), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
		}
	}
	for _, mi := range miList {
		principals = append(principals, Principal{
			Service:     "Azure Resource",
			Type:        "UserAssignedManagedIdentity",
			UPN:         azinternal.SafeString(mi.Name),
			DisplayName: azinternal.SafeString(mi.Name),
			PrincipalID: azinternal.SafeString(mi.PrincipalID),
			Extra:       map[string]string{"ResourceID": azinternal.SafeString(mi.ResourceID), "Subscription": azinternal.SafeString(mi.SubscriptionID)},
		})
	}

	// Context label for output
	var contextLabel string
	if m.TenantName != "" {
		contextLabel = m.TenantName
	} else if len(m.Subscriptions) > 0 {
		subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, m.Subscriptions[0])
		if subName == "" {
			subName = m.Subscriptions[0]
		}
		contextLabel = subName
	} else if m.TenantID != "" {
		// Use tenant ID as final fallback instead of "Unknown Context"
		contextLabel = m.TenantID
	} else {
		contextLabel = "Unknown Context"
	}

	// Build subscription name map for RBAC lookups
	subNameMap := map[string]string{}
	for _, s := range m.TenantInfo.Subscriptions {
		subNameMap[s.ID] = s.Name
	}

	// Process principals with controlled concurrency using worker pool
	// This prevents network timeouts from too many simultaneous API calls
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, m.Goroutines) // Limit concurrent workers

	for _, p := range principals {
		wg.Add(1)
		go func(principal Principal) {
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore
			m.processPrincipal(ctx, principal, contextLabel, subNameMap, &wg)
		}(p)
	}

	wg.Wait()
}

// ------------------------------
// Process single principal
// ------------------------------
func (m *PrincipalsModule) processPrincipal(ctx context.Context, p Principal, contextLabel string, subNameMap map[string]string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Normalize fields
	upn := p.UPN
	if upn == "" {
		upn = "N/A"
	}
	dname := p.DisplayName
	if dname == "" {
		dname = "N/A"
	}
	pid := p.PrincipalID
	if pid == "" {
		pid = "N/A"
	}

	logger := internal.NewLogger()

	// Get nested group memberships (for display) - works for all principal types
	// Groups can also be members of other groups (nested hierarchy)
	groupMemberships := ""
	directGroups, allGroups, err := azinternal.GetNestedGroupMemberships(ctx, m.Session, p.PrincipalID)
	if err == nil {
		groupMemberships = azinternal.FormatNestedGroupMemberships(directGroups, allGroups)
	}

	// Get Enhanced RBAC assignments with inheritance tracking from all scopes
	// This includes: Tenant Root (/), Management Groups, Subscription, Resource Groups, Resources
	var allRBACWithInheritance []string
	var allPIMEligible []string
	var allPIMActive []string
	inheritedPermissions := []string{}

	for _, sub := range m.Subscriptions {
		subDisplayName := subNameMap[sub]
		if subDisplayName == "" {
			subDisplayName = sub
		}

		// Get enhanced RBAC with full scope hierarchy and inheritance tracking
		rbacAssignments, err := azinternal.GetEnhancedRBACAssignments(ctx, m.Session, p.PrincipalID, sub)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to get enhanced RBAC for principal %s in subscription %s: %v", p.PrincipalID, sub, err), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
		} else {
			for _, assignment := range rbacAssignments {
				// Build RBAC display string
				rbacDisplay := fmt.Sprintf("%s: %s", subDisplayName, assignment.RoleName)
				if assignment.AssignedVia == "Group" {
					rbacDisplay += " (via Group)"
				}
				// Add scope type for clarity
				if assignment.ScopeType == "TenantRoot" {
					rbacDisplay += " [Tenant Root]"
				} else if assignment.ScopeType == "ManagementGroup" {
					rbacDisplay += fmt.Sprintf(" [MG: %s]", assignment.ScopeDisplayName)
				}
				allRBACWithInheritance = append(allRBACWithInheritance, rbacDisplay)

				// Track inherited permissions
				if assignment.InheritedFrom != "" {
					inheritedPermissions = append(inheritedPermissions,
						fmt.Sprintf("%s: %s (inherited from %s)",
							subDisplayName, assignment.RoleName, assignment.ScopeType))
				}
			}
		}

		// Get PIM Eligible roles
		principalIDs := []string{p.PrincipalID}
		// For users, also check their group memberships for PIM assignments
		if p.Type == "User" || p.Type == "Guest" {
			groupIDs := azinternal.GetUserGroupMemberships(ctx, m.Session, p.PrincipalID)
			principalIDs = append(principalIDs, groupIDs...)
		}

		pimEligible, err := azinternal.GetPIMEligibleRoles(ctx, m.Session, sub, principalIDs)
		if err == nil {
			for _, pimRole := range pimEligible {
				pimDisplay := fmt.Sprintf("%s: %s (%s)", subDisplayName, pimRole.RoleName, pimRole.AssignedVia)
				allPIMEligible = append(allPIMEligible, pimDisplay)
			}
		}

		// Get PIM Active roles
		pimActive, err := azinternal.GetPIMActiveRoles(ctx, m.Session, sub, principalIDs)
		if err == nil {
			for _, pimRole := range pimActive {
				pimDisplay := fmt.Sprintf("%s: %s (%s)", subDisplayName, pimRole.RoleName, pimRole.AssignedVia)
				allPIMActive = append(allPIMActive, pimDisplay)
			}
		}
	}

	// Format RBAC roles with PIM status inline
	rbacStr := ""
	if len(allRBACWithInheritance) > 0 {
		rbacStr = strings.Join(allRBACWithInheritance, "\n")
	}

	// Format PIM information
	pimStr := ""
	if len(allPIMEligible) > 0 {
		pimStr = "Eligible: " + strings.Join(allPIMEligible, ", ")
	}
	if len(allPIMActive) > 0 {
		if pimStr != "" {
			pimStr += "\n"
		}
		pimStr += "Active: " + strings.Join(allPIMActive, ", ")
	}

	// Format inherited permissions
	inheritedStr := ""
	if len(inheritedPermissions) > 0 {
		inheritedStr = strings.Join(inheritedPermissions, "\n")
	}

	// Get Entra ID Directory Roles (Global Admin, User Admin, etc.)
	var allDirectoryRoles []azinternal.DirectoryRole
	var allPIMEligibleDirectoryRoles []azinternal.DirectoryRole
	var allPIMActiveDirectoryRoles []azinternal.DirectoryRole

	// Get permanent directory role assignments
	directoryRoles, err := azinternal.GetDirectoryRolesForPrincipal(ctx, m.Session, p.PrincipalID)
	if err == nil {
		allDirectoryRoles = append(allDirectoryRoles, directoryRoles...)
	}

	// Get PIM-eligible directory roles
	pimEligibleDirRoles, err := azinternal.GetPIMEligibleDirectoryRoles(ctx, m.Session, p.PrincipalID)
	if err == nil {
		allPIMEligibleDirectoryRoles = append(allPIMEligibleDirectoryRoles, pimEligibleDirRoles...)
	}

	// Get PIM-active directory roles
	pimActiveDirRoles, err := azinternal.GetPIMActiveDirectoryRoles(ctx, m.Session, p.PrincipalID)
	if err == nil {
		allPIMActiveDirectoryRoles = append(allPIMActiveDirectoryRoles, pimActiveDirRoles...)
	}

	// Format directory roles
	directoryRolesStr := azinternal.FormatDirectoryRoles(allDirectoryRoles)

	// Enhance PIM string to include directory roles
	if len(allPIMEligibleDirectoryRoles) > 0 {
		if pimStr != "" {
			pimStr += "\n"
		}
		eligibleDirRoles := []string{}
		for _, role := range allPIMEligibleDirectoryRoles {
			eligibleDirRoles = append(eligibleDirRoles, fmt.Sprintf("%s (Entra ID)", role.DisplayName))
		}
		pimStr += "Eligible Directory: " + strings.Join(eligibleDirRoles, ", ")
	}
	if len(allPIMActiveDirectoryRoles) > 0 {
		if pimStr != "" {
			pimStr += "\n"
		}
		activeDirRoles := []string{}
		for _, role := range allPIMActiveDirectoryRoles {
			activeDirRoles = append(activeDirRoles, fmt.Sprintf("%s (Entra ID)", role.DisplayName))
		}
		pimStr += "Active Directory: " + strings.Join(activeDirRoles, ", ")
	}

	// Get Conditional Access Policies
	caPolicies, err := azinternal.GetConditionalAccessPoliciesForPrincipal(ctx, m.Session, p.PrincipalID)
	caStr := ""
	if err == nil && len(caPolicies) > 0 {
		caStr = azinternal.FormatConditionalAccessPolicies(caPolicies)
	}

	// Get Graph API permissions
	permissions := azinternal.GetPrincipalPermissions(ctx, m.Session, p.PrincipalID)
	graphPerms := permissions.Graph

	// Get OAuth2 delegated grants
	delegatedPerms := azinternal.GetDelegatedOAuth2Grants(ctx, m.Session, p.PrincipalID)
	delegatedStr := ""
	if len(delegatedPerms) > 0 {
		delegatedStr = strings.Join(delegatedPerms, ", ")
	}

	// Get MFA authentication methods (only for User and Guest types)
	mfaEnabled := "N/A"
	mfaMethods := "N/A"
	mfaDefaultMethod := "N/A"
	if p.Type == "User" || p.Type == "Guest" {
		mfaInfo, err := azinternal.GetUserMFAAuthenticationMethods(ctx, m.Session, p.PrincipalID)
		if err == nil {
			if mfaInfo.MFAEnabled {
				mfaEnabled = "Yes"
				mfaMethods = strings.Join(mfaInfo.Methods, ", ")
				if mfaInfo.DefaultMethod != "" {
					mfaDefaultMethod = mfaInfo.DefaultMethod
				}
			} else {
				mfaEnabled = "No"
				mfaMethods = "None"
				mfaDefaultMethod = "None"
			}
		}
	}

	// Get sign-in activity (only for User and Guest types)
	lastSignIn := "N/A"
	lastNonInteractiveSignIn := "N/A"
	daysSinceSignIn := "N/A"
	staleAccount := "No"
	if p.Type == "User" || p.Type == "Guest" {
		signInActivity, err := azinternal.GetUserSignInActivity(ctx, m.Session, p.PrincipalID)
		if err == nil {
			// Format last sign-in datetime
			if signInActivity.LastSignInDateTime != "Never" {
				if t, parseErr := time.Parse(time.RFC3339, signInActivity.LastSignInDateTime); parseErr == nil {
					lastSignIn = t.Format("2006-01-02 15:04")
				} else {
					lastSignIn = signInActivity.LastSignInDateTime
				}
			} else {
				lastSignIn = "Never"
			}

			// Format last non-interactive sign-in
			if signInActivity.LastNonInteractiveSignInDateTime != "Never" {
				if t, parseErr := time.Parse(time.RFC3339, signInActivity.LastNonInteractiveSignInDateTime); parseErr == nil {
					lastNonInteractiveSignIn = t.Format("2006-01-02 15:04")
				} else {
					lastNonInteractiveSignIn = signInActivity.LastNonInteractiveSignInDateTime
				}
			} else {
				lastNonInteractiveSignIn = "Never"
			}

			// Days since last sign-in
			if signInActivity.DaysSinceLastSignIn >= 0 {
				daysSinceSignIn = fmt.Sprintf("%d days", signInActivity.DaysSinceLastSignIn)
			} else {
				daysSinceSignIn = "Never"
			}

			// Stale account flag
			if signInActivity.IsStale {
				staleAccount = fmt.Sprintf("⚠ Yes (%s)", signInActivity.StaleReason)
			}
		}
	}

	// Thread-safe append - table row with new columns including tenant info
	m.mu.Lock()
	m.PrincipalRows = append(m.PrincipalRows, []string{
		m.TenantName, // NEW: Tenant Name (for multi-tenant support)
		m.TenantID,   // NEW: Tenant ID (for multi-tenant support)
		contextLabel,
		p.Service,
		p.Type,
		upn,
		dname,
		pid,
		mfaEnabled,               // MFA Enabled (Yes/No/N/A)
		mfaMethods,               // MFA Methods (Phone, Authenticator, FIDO2, etc.)
		mfaDefaultMethod,         // Default MFA Method
		lastSignIn,               // Last Sign-In (Interactive)
		lastNonInteractiveSignIn, // Last Sign-In (Non-Interactive)
		daysSinceSignIn,          // Days Since Last Sign-In
		staleAccount,             // Stale Account (>90 days or never)
		groupMemberships,         // Group memberships (with nested)
		rbacStr,                  // Enhanced with scope hierarchy
		directoryRolesStr,        // Entra ID Directory Roles
		pimStr,                   // PIM Eligible/Active (Azure RBAC + Directory Roles)
		inheritedStr,             // Inherited permissions
		caStr,                    // Conditional Access Policies
		graphPerms,               // Graph API Permissions
		delegatedStr,             // OAuth2 Delegated Grants
	})

	// Loot: generate az & PowerShell commands
	m.LootMap["principal-commands"].Contents += m.generateLootForPrincipal(p)
	m.mu.Unlock()
}

// ------------------------------
// Generate loot commands for principal
// ------------------------------
func (m *PrincipalsModule) generateLootForPrincipal(pr Principal) string {
	loot := fmt.Sprintf("## Principal: %s (%s)\n", pr.DisplayName, pr.PrincipalID)
	loot += fmt.Sprintf("## Set tenant context\naz account clear\naz login --tenant %s\n\n", m.TenantID)

	switch strings.ToLower(pr.Type) {
	case "user", "guest":
		if pr.UPN != "" && pr.UPN != "N/A" {
			loot += fmt.Sprintf("# az (user)\naz ad user show --id \"%s\"\n", pr.UPN)
		}
		if pr.PrincipalID != "" && pr.PrincipalID != "N/A" {
			loot += fmt.Sprintf("az ad user show --id %s\n", pr.PrincipalID)
		}
		loot += fmt.Sprintf("az rest --method get --uri \"https://graph.microsoft.com/v1.0/users/%s\"\n", azinternal.SafeString(pr.PrincipalID))
		loot += fmt.Sprintf("## PowerShell (AzureAD/Microsoft.Graph)\n# AzureAD module\nGet-AzureADUser -ObjectId \"%s\"\n# Microsoft.Graph module\nGet-MgUser -UserId \"%s\"\n\n", pr.PrincipalID, pr.PrincipalID)

	case "serviceprincipal", "service principal":
		if pr.PrincipalID != "" && pr.PrincipalID != "N/A" {
			loot += fmt.Sprintf("# az (service principal)\naz ad sp show --id %s\n", pr.PrincipalID)
			loot += fmt.Sprintf("az rest --method get --uri \"https://graph.microsoft.com/v1.0/servicePrincipals/%s\"\n", azinternal.SafeString(pr.PrincipalID))
			loot += fmt.Sprintf("## PowerShell (AzureAD/Microsoft.Graph)\nGet-AzureADServicePrincipal -ObjectId \"%s\"\nGet-MgServicePrincipal -ServicePrincipalId \"%s\"\n\n", pr.PrincipalID, pr.PrincipalID)
		} else if pr.UPN != "" && pr.UPN != "N/A" {
			loot += fmt.Sprintf("az ad sp show --id \"%s\"\n", pr.UPN)
		}
		loot += fmt.Sprintf("# Check role assignments for this principal\naz role assignment list --assignee %s\n", pr.PrincipalID)

	case "userassignedmanagedidentity", "managedidentity", "userassigned":
		if rid, ok := pr.Extra["ResourceID"]; ok && rid != "" {
			loot += fmt.Sprintf("# az (user-assigned managed identity)\naz resource show --ids %s\n", rid)
			loot += fmt.Sprintf("az identity show --ids %s\n", rid)
			loot += fmt.Sprintf("## Find role assignments for the identity\naz role assignment list --assignee %s\n\n", pr.PrincipalID)
		} else {
			loot += fmt.Sprintf("# Managed Identity: try role assignment lookup\naz role assignment list --assignee %s\n\n", pr.PrincipalID)
		}

	default:
		if pr.PrincipalID != "" && pr.PrincipalID != "N/A" {
			loot += fmt.Sprintf("# Generic: try Graph lookup\naz rest --method get --uri \"https://graph.microsoft.com/v1.0/directoryObjects/%s\"\n", azinternal.SafeString(pr.PrincipalID))
			loot += fmt.Sprintf("az role assignment list --assignee %s\n", pr.PrincipalID)
			loot += fmt.Sprintf("Get-AzureADDirectoryObject -ObjectId \"%s\"\nGet-MgDirectoryObject -DirectoryObjectId \"%s\"\n\n", pr.PrincipalID, pr.PrincipalID)
		}
	}

	loot += fmt.Sprintf("# Check what subscriptions you can access (context)\naz account list --all -o table\n\n")
	return loot
}

// ------------------------------
// Write output
// ------------------------------
func (m *PrincipalsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.PrincipalRows) == 0 {
		logger.InfoM("No Principals found", globals.AZ_PRINCIPALS_MODULE_NAME)
		return
	}

	// Build headers with new columns
	headers := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Tenant/Subscription Context",
		"Source Service",
		"Principal Type",
		"User Principal Name / App ID",
		"Display Name",
		"Object ID",
		"MFA Enabled",                       // MFA status (Yes/No/N/A)
		"MFA Methods",                       // MFA methods (Phone, Authenticator, FIDO2, etc.)
		"Default MFA Method",                // Default MFA method
		"Last Sign-In (Interactive)",        // Last interactive sign-in
		"Last Sign-In (Non-Interactive)",    // Last non-interactive sign-in
		"Days Since Last Sign-In",           // Days since last sign-in
		"Stale Account (>90 days)",          // Stale account flag
		"Group Memberships (incl. Nested)",  // With nested groups
		"RBAC Roles (with Scope Hierarchy)", // Enhanced
		"Entra ID Directory Roles",          // Directory roles (Global Admin, etc.)
		"PIM Status (Eligible/Active)",      // Azure RBAC + Directory Roles PIM
		"Inherited Permissions",
		"Conditional Access Policies",
		"Graph API Permissions",
		"Delegated OAuth2 Grants",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.PrincipalRows,
			headers,
			"principals",
			globals.AZ_PRINCIPALS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.PrincipalRows, headers,
			"principals", globals.AZ_PRINCIPALS_MODULE_NAME,
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
	output := PrincipalsOutput{
		Table: []internal.TableFile{{
			Name:   "principals",
			Header: headers,
			Body:   m.PrincipalRows,
		}},
		Loot: loot,
	}

	// Tenant-level module - determine scope based on multi-tenant mode
	var scopeType string
	var scopeIDs []string
	var scopeNames []string

	if m.IsMultiTenant {
		// Multi-tenant: use first tenant for consolidated output (tenant splitting handled above)
		scopeType = "tenant"
		scopeIDs = []string{m.TenantID}
		scopeNames = []string(nil)
	} else {
		// Single tenant
		scopeType = "tenant"
		scopeIDs = []string{m.TenantID}
		scopeNames = []string(nil)
	}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Principal(s) for tenant: %s", len(m.PrincipalRows), m.TenantName), globals.AZ_PRINCIPALS_MODULE_NAME)
}
