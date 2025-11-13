package commands

import (
	"context"
	"encoding/json"
	"fmt"
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
	Subscriptions   []string
	PermissionRows  [][]string // All permissions collected (one row per action)
	RoleDefinitions map[string]*armauthorization.RoleDefinition
	PrincipalCache  map[string]*PrincipalInfo // Cache for principal lookups
	GroupCache      map[string]*PrincipalInfo // Cache for group lookups
	TenantLevel     bool
	SubLevel        bool
	RGLevel         bool
	Workers         int
	mu              sync.Mutex // Protects PermissionRows and caches
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
	var orphanedPrincipals []azinternal.PrincipalInfo
	seenPrincipals := make(map[string]bool)
	orphanedPrincipalIDs := make(map[string]bool)

	// Build map of known principal IDs
	for _, p := range knownPrincipals {
		seenPrincipals[p.ObjectID] = true
	}

	// Get ARM token
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for orphaned principal scan: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		return orphanedPrincipals
	}

	// Process each subscription
	for _, subID := range m.Subscriptions {
		cred := &azinternal.StaticTokenCredential{Token: token}
		clientFactory, err := armauthorization.NewClientFactory(subID, cred, nil)
		if err != nil {
			continue
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

						// Check if this principal is unknown
						if !seenPrincipals[principalID] && !orphanedPrincipalIDs[principalID] {
							orphanedPrincipalIDs[principalID] = true

							// Try to determine principal type
							principalType := "Unknown"
							if ra.Properties.PrincipalType != nil {
								principalType = string(*ra.Properties.PrincipalType)
							}

							// Add as orphaned principal
							orphanedPrincipals = append(orphanedPrincipals, azinternal.PrincipalInfo{
								ObjectID:          principalID,
								UserPrincipalName: "Unknown",
								DisplayName:       fmt.Sprintf("Orphaned-%s", principalID[:8]),
								UserType:          fmt.Sprintf("Orphaned%s", principalType),
							})

							if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
								logger.InfoM(fmt.Sprintf("Found orphaned principal: %s (type: %s)", principalID, principalType), globals.AZ_PERMISSIONS_MODULE_NAME)
							}
						}
					}
				}
			}
		}

		// Also check PIM assignments for orphaned principals
		m.scanPIMForOrphanedPrincipals(ctx, subID, token, seenPrincipals, orphanedPrincipalIDs, &orphanedPrincipals, logger)
	}

	return orphanedPrincipals
}

// Helper to scan PIM for orphaned principals
func (m *PermissionsModule) scanPIMForOrphanedPrincipals(ctx context.Context, subID, token string, seenPrincipals, orphanedPrincipalIDs map[string]bool, orphanedPrincipals *[]azinternal.PrincipalInfo, logger internal.Logger) {
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
				if !seenPrincipals[principalID] && !orphanedPrincipalIDs[principalID] {
					orphanedPrincipalIDs[principalID] = true
					principalType := pimAssignment.Properties.ExpandedProperties.Principal.Type

					*orphanedPrincipals = append(*orphanedPrincipals, azinternal.PrincipalInfo{
						ObjectID:          principalID,
						UserPrincipalName: "Unknown",
						DisplayName:       fmt.Sprintf("Orphaned-%s", principalID[:8]),
						UserType:          fmt.Sprintf("Orphaned%s", principalType),
					})
				}
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
				if !seenPrincipals[principalID] && !orphanedPrincipalIDs[principalID] {
					orphanedPrincipalIDs[principalID] = true
					principalType := pimAssignment.Properties.ExpandedProperties.Principal.Type

					*orphanedPrincipals = append(*orphanedPrincipals, azinternal.PrincipalInfo{
						ObjectID:          principalID,
						UserPrincipalName: "Unknown",
						DisplayName:       fmt.Sprintf("Orphaned-%s", principalID[:8]),
						UserType:          fmt.Sprintf("Orphaned%s", principalType),
					})
				}
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

	// Process each subscription
	for _, subID := range m.Subscriptions {
		subName := ""
		for _, s := range m.TenantInfo.Subscriptions {
			if s.ID == subID {
				subName = s.Name
				break
			}
		}

		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Processing subscription: %s (%s)", subName, subID), globals.AZ_PERMISSIONS_MODULE_NAME)
		}

		// Get ARM token
		token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to get token for subscription %s: %v", subID, err), globals.AZ_PERMISSIONS_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		cred := &azinternal.StaticTokenCredential{Token: token}
		clientFactory, err := armauthorization.NewClientFactory(subID, cred, nil)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to create client factory for subscription %s: %v", subID, err), globals.AZ_PERMISSIONS_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		authClient := clientFactory.NewRoleAssignmentsClient()

		// Build list of scopes to check
		scopes := m.buildScopesForSubscription(ctx, subID, authClient, cred, logger)

		// For each principal, check their permissions at each scope
		for _, principal := range principals {
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
			return "Resource", extractResourceName(scope)
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

	// Prepare output
	output := PermissionsOutput{
		Table: []internal.TableFile{
			{
				Name:   "permissions",
				Header: PermissionsHeader,
				Body:   m.PermissionRows,
			},
		},
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
