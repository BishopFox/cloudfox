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
var AzRBACCommand = &cobra.Command{
	Use:     "rbac",
	Aliases: []string{"roles", "permissions"},
	Short:   "Enumerate Azure RBAC assignments with comprehensive coverage",
	Long: `
Enumerate ALL RBAC permissions across all scopes and principals:

Comprehensive enumeration includes:
  - Tenant root (/) assignments
  - Management group hierarchy assignments
  - Subscription-level assignments
  - Resource group-level assignments
  - Individual resource-level assignments
  - PIM (Privileged Identity Management) eligible assignments
  - PIM active assignments
  - Inherited permissions from parent scopes

Usage:
  ./cloudfox az rbac --tenant TENANT_ID --subscription SUBSCRIPTION_ID
  ./cloudfox az rbac --tenant TENANT_ID --subscription SUBSCRIPTION_ID --resource-group-level
  
Flags:
  --tenant-level           Enumerate tenant root and management group assignments
  --subscription-level     Enumerate subscription-level assignments
  --resource-group-level   Enumerate resource group and individual resource assignments
  (If no flags specified, all levels are enumerated by default)`,
	Run: ListRBAC,
}

// ======================
// Output struct
// ======================
type RBACOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

// rbacAssignmentWithMeta wraps a role assignment with additional metadata for tracking
type rbacAssignmentWithMeta struct {
	Assignment  *armauthorization.RoleAssignment
	AssignedVia string
	IsPIM       bool
	IsPIMActive bool
}

// RBACModule implements RBAC enumeration using BaseAzureModule pattern
type RBACModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	RBACRows      [][]string // All RBAC assignments collected (as table rows)
	TenantLevel   bool
	SubLevel      bool
	RGLevel       bool
	NoDedupe      bool
	Workers       int
	Channels      int
	mu            sync.Mutex // Protects RBACRows
}

var (
	noDedupe       bool
	runTenantLevel bool
	runSubLevel    bool
	runRGLevel     bool
	workers        int
	channels       int
)

var RBACHeader = []string{
	"Principal GUID",
	"Principal Name / Application Name",
	"Principal UPN / Application ID",
	"Principal Type",
	"Role Name",
	"Providers/Resources",
	"Assigned Via",
	"Nested Groups",
	"Tenant Name",        // New: for multi-tenant support
	"Tenant ID",          // New: for multi-tenant support
	"Tenant Scope",       // Existing: /
	"Subscription Scope", // Existing: subscription name
	"Resource Group Scope",
	"Full Scope",
	"Condition",
	"Delegated Managed Identity Resource",
}

func (o RBACOutput) TableFiles() []internal.TableFile { return o.Table }
func (o RBACOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ======================
// Init flags
// ======================
func init() {
	//	AzRBACCommand.Flags().String("group-by", "", "Group output by user|role|scope")
	//	AzRBACCommand.Flags().Bool("verbose-json", false, "Include full raw role assignment JSON in output")
	//	AzRBACCommand.Flags().Bool("per-principal", false, "Create separate loot files per principal")
	AzRBACCommand.Flags().BoolVar(&runTenantLevel, "tenant-level", false, "Run tenant-level RBAC enumeration")
	AzRBACCommand.Flags().BoolVar(&runSubLevel, "subscription-level", false, "Run subscription-level RBAC enumeration")
	AzRBACCommand.Flags().BoolVar(&runRGLevel, "resource-group-level", false, "Run resource group-level RBAC enumeration")
	AzRBACCommand.Flags().BoolVar(&noDedupe, "no-dedupe", false, "Disable deduplication and return every permission")
	AzRBACCommand.Flags().IntVar(&channels, "channels", 100, "Number of streaming channels to spawn concurrently")
	AzRBACCommand.Flags().IntVar(&workers, "workers", 10, "Number of workers to spawn concurrently")
}

// ======================
// Main handler
// ======================
func ListRBAC(cmd *cobra.Command, args []string) {
	// Initialize command context (handles all flag parsing, session creation, tenant/subscription resolution)
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_RBAC_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	// Parse RBAC-specific flags
	tenantLevel, _ := cmd.Flags().GetBool("tenant-level")
	subLevel, _ := cmd.Flags().GetBool("subscription-level")
	rgLevel, _ := cmd.Flags().GetBool("resource-group-level")
	noDedupe, _ := cmd.Flags().GetBool("no-dedupe")
	workers, _ := cmd.Flags().GetInt("workers")
	channels, _ := cmd.Flags().GetInt("channels")

	// Default: if no levels specified, run all levels
	if !tenantLevel && !subLevel && !rgLevel {
		if cmdCtx.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			cmdCtx.Logger.InfoM("No levels specified; defaulting to all levels", globals.AZ_RBAC_MODULE_NAME)
		}
		tenantLevel = true
		subLevel = true
		rgLevel = true
	}

	// Initialize module
	module := &RBACModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 13), // 13 columns in header
		Subscriptions:   cmdCtx.Subscriptions,
		RBACRows:        [][]string{},
		TenantLevel:     tenantLevel,
		SubLevel:        subLevel,
		RGLevel:         rgLevel,
		NoDedupe:        noDedupe,
		Workers:         workers,
		Channels:        channels,
	}

	// Execute module
	module.PrintRBAC(cmdCtx.Ctx, cmdCtx.Logger)
}

// ======================
// PrintRBAC - Main enumeration orchestrator
// ======================
func (m *RBACModule) PrintRBAC(ctx context.Context, logger internal.Logger) {
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Starting RBAC enumeration", globals.AZ_RBAC_MODULE_NAME)
		if m.IsMultiTenant {
			logger.InfoM(fmt.Sprintf("Multi-tenant mode: %d tenants", len(m.Tenants)), globals.AZ_RBAC_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("Tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_RBAC_MODULE_NAME)
		}
		logger.InfoM(fmt.Sprintf("Subscriptions: %d", len(m.Subscriptions)), globals.AZ_RBAC_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Levels: Tenant=%v, Subscription=%v, ResourceGroup=%v",
			m.TenantLevel, m.SubLevel, m.RGLevel), globals.AZ_RBAC_MODULE_NAME)
	}

	// Multi-tenant processing
	if m.IsMultiTenant {
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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_RBAC_MODULE_NAME)
			}

			// Enumerate tenant-level RBAC if requested
			if m.TenantLevel && len(tenantCtx.Subscriptions) > 0 {
				m.processTenantLevel(ctx, logger)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions,
				globals.AZ_RBAC_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		// Enumerate tenant-level RBAC first (if requested) using a tenant-scoped client
		if m.TenantLevel && len(m.Subscriptions) > 0 {
			m.processTenantLevel(ctx, logger)
		}

		// Use RunSubscriptionEnumeration to process all subscriptions with automatic goroutine management
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions,
			globals.AZ_RBAC_MODULE_NAME, m.processSubscription)
	}

	// Show completion status
	totalSubs := len(m.Subscriptions)
	errors := m.CommandCounter.Error
	logger.InfoM(fmt.Sprintf("Status: %d/%d subscriptions complete (%d errors -- For details check %s/cloudfox-error.log)",
		totalSubs-errors, totalSubs, errors, m.OutputDirectory), globals.AZ_RBAC_MODULE_NAME)

	// Write all collected data
	m.writeOutput(ctx, logger)
}

// ======================
// processSubscription - Process a single subscription with full coverage
// ======================
func (m *RBACModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Processing subscription: %s", subID), globals.AZ_RBAC_MODULE_NAME)
	}

	// Get subscription name
	subName := ""
	for _, s := range m.TenantInfo.Subscriptions {
		if s.ID == subID {
			subName = s.Name
			break
		}
	}

	// Get token for ARM scope
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for subscription %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}

	// Create authorization client factory for this subscription
	clientFactory, err := armauthorization.NewClientFactory(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create authorization client factory for %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	authClient := clientFactory.NewRoleAssignmentsClient()
	roleDefClient := clientFactory.NewRoleDefinitionsClient()

	// Cache role definitions for this subscription
	subScope := fmt.Sprintf("/subscriptions/%s", subID)
	roleDefs := m.cacheRoleDefinitions(ctx, roleDefClient, subScope, logger)

	// Collect ALL role assignments based on scope levels
	var allAssignments []rbacAssignmentWithMeta

	// 1. Check management group hierarchy for ALL assignments
	mgHierarchy := azinternal.GetManagementGroupHierarchy(ctx, m.Session, subID)
	if len(mgHierarchy) > 0 && m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d management groups in hierarchy", len(mgHierarchy)), globals.AZ_RBAC_MODULE_NAME)
	}

	for _, mgID := range mgHierarchy {
		mgScope := fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID)
		assignments := m.listRoleAssignments(ctx, authClient, mgScope, logger)
		for _, ra := range assignments {
			allAssignments = append(allAssignments, rbacAssignmentWithMeta{
				Assignment:  ra,
				AssignedVia: m.determineAssignedViaFromProperties(ra, false, false),
			})
		}
	}

	// 2. Subscription-level assignments (includes inherited assignments from parent scopes)
	if m.SubLevel {
		subAssignments := m.listRoleAssignmentsForSubscription(ctx, authClient, logger)
		for _, ra := range subAssignments {
			allAssignments = append(allAssignments, rbacAssignmentWithMeta{
				Assignment:  ra,
				AssignedVia: m.determineAssignedViaFromProperties(ra, false, false),
			})
		}
	}

	// 3. Resource-group-level assignments
	if m.RGLevel {
		rgAssignments := m.listResourceGroupAssignments(ctx, subID, authClient, cred, logger)
		for _, ra := range rgAssignments {
			allAssignments = append(allAssignments, rbacAssignmentWithMeta{
				Assignment:  ra,
				AssignedVia: m.determineAssignedViaFromProperties(ra, false, false),
			})
		}

		// Also enumerate individual resource-level assignments
		resourceAssignments := m.listResourceLevelAssignments(ctx, subID, authClient, cred, logger)
		for _, ra := range resourceAssignments {
			allAssignments = append(allAssignments, rbacAssignmentWithMeta{
				Assignment:  ra,
				AssignedVia: m.determineAssignedViaFromProperties(ra, false, false),
			})
		}
	}

	// 4. Check PIM Eligibility Schedules for ALL principals
	pimEligible := m.getAllPIMEligibilitySchedules(ctx, subID, logger)
	for _, pim := range pimEligible {
		allAssignments = append(allAssignments, rbacAssignmentWithMeta{
			Assignment:  pim,
			AssignedVia: m.determineAssignedViaFromProperties(pim, true, false),
			IsPIM:       true,
			IsPIMActive: false,
		})
	}

	// 5. Check PIM Active Schedules for ALL principals
	pimActive := m.getAllPIMActiveSchedules(ctx, subID, logger)
	for _, pim := range pimActive {
		allAssignments = append(allAssignments, rbacAssignmentWithMeta{
			Assignment:  pim,
			AssignedVia: m.determineAssignedViaFromProperties(pim, false, true),
			IsPIM:       true,
			IsPIMActive: true,
		})
	}

	// Deduplicate if needed
	if !m.NoDedupe {
		allAssignments = m.deduplicateAssignmentsWithMeta(allAssignments)
	}

	// Convert to rows and store (creates multiple rows per assignment, one per provider)
	for _, meta := range allAssignments {
		rows := m.buildRBACTableRowsWithMeta(ctx, meta, subID, subName, roleDefs, logger)
		m.mu.Lock()
		m.RBACRows = append(m.RBACRows, rows...)
		m.mu.Unlock()
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Collected %d total RBAC assignments from %s", len(allAssignments), subID), globals.AZ_RBAC_MODULE_NAME)
	}
}

// ======================
// processTenantLevel - Process tenant-level RBAC with tenant-scoped client
// ======================
func (m *RBACModule) processTenantLevel(ctx context.Context, logger internal.Logger) {
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Processing tenant-level RBAC: %s", m.TenantName), globals.AZ_RBAC_MODULE_NAME)
	}

	// Get token for ARM scope
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for tenant-level query: %v", err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}

	// Use tenant ID to create client factory for tenant-level queries
	clientFactory, err := armauthorization.NewClientFactory(m.TenantID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create authorization client factory for tenant-level query: %v", err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	authClient := clientFactory.NewRoleAssignmentsClient()
	roleDefClient := clientFactory.NewRoleDefinitionsClient()

	// Query tenant-level assignments using root scope "/"
	tenantScope := "/"

	// Cache role definitions for tenant scope
	roleDefs := m.cacheRoleDefinitions(ctx, roleDefClient, tenantScope, logger)

	tenantAssignments := m.listRoleAssignments(ctx, authClient, tenantScope, logger)

	// Deduplicate if needed
	if !m.NoDedupe {
		tenantAssignments = m.deduplicateAssignments(tenantAssignments)
	}

	// Convert to rows and store (creates multiple rows per assignment, one per provider)
	for _, ra := range tenantAssignments {
		rows := m.buildRBACTableRows(ra, "", m.TenantName, roleDefs) // No subID for tenant-level
		m.mu.Lock()
		m.RBACRows = append(m.RBACRows, rows...)
		m.mu.Unlock()
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Collected %d tenant-level RBAC assignments", len(tenantAssignments)), globals.AZ_RBAC_MODULE_NAME)
	}
}

// ======================
// Helper Methods
// ======================

// listRoleAssignments lists role assignments for a given scope
func (m *RBACModule) listRoleAssignments(ctx context.Context, client *armauthorization.RoleAssignmentsClient,
	scope string, logger internal.Logger) []*armauthorization.RoleAssignment {

	var assignments []*armauthorization.RoleAssignment

	pager := client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: nil,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// Always log errors to file, regardless of verbosity
			logger.ErrorM(fmt.Sprintf("Failed to list role assignments for scope %s: %v", scope, err), globals.AZ_RBAC_MODULE_NAME)
			m.CommandCounter.Error++
			break
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments
}

// listRoleAssignmentsForSubscription lists ALL role assignments for a subscription including inherited ones
// This uses NewListForSubscriptionPager which returns assignments at the subscription level AND
// inherited assignments from parent scopes (management groups, tenant root, etc.)
func (m *RBACModule) listRoleAssignmentsForSubscription(ctx context.Context, client *armauthorization.RoleAssignmentsClient,
	logger internal.Logger) []*armauthorization.RoleAssignment {

	var assignments []*armauthorization.RoleAssignment

	pager := client.NewListForSubscriptionPager(&armauthorization.RoleAssignmentsClientListForSubscriptionOptions{
		Filter: nil,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// Always log errors to file, regardless of verbosity
			logger.ErrorM(fmt.Sprintf("Failed to list subscription role assignments: %v", err), globals.AZ_RBAC_MODULE_NAME)
			m.CommandCounter.Error++
			break
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments
}

// listResourceGroupAssignments lists role assignments for all resource groups in a subscription
func (m *RBACModule) listResourceGroupAssignments(ctx context.Context, subID string,
	authClient *armauthorization.RoleAssignmentsClient, cred *azinternal.StaticTokenCredential, logger internal.Logger) []*armauthorization.RoleAssignment {

	var assignments []*armauthorization.RoleAssignment

	// Get resource groups using the provided credential
	rgClient, err := armresources.NewResourceGroupsClient(subID, cred, nil)
	if err != nil {
		return assignments
	}

	pager := rgClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, rg := range page.Value {
			if rg.ID != nil {
				rgAssignments := m.listRoleAssignments(ctx, authClient, *rg.ID, logger)
				assignments = append(assignments, rgAssignments...)
			}
		}
	}

	return assignments
}

// listResourceLevelAssignments lists role assignments for all individual resources in a subscription
func (m *RBACModule) listResourceLevelAssignments(ctx context.Context, subID string,
	authClient *armauthorization.RoleAssignmentsClient, cred *azinternal.StaticTokenCredential, logger internal.Logger) []*armauthorization.RoleAssignment {

	var assignments []*armauthorization.RoleAssignment

	// Get all resources in the subscription
	resourcesClient, err := armresources.NewClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create resources client for subscription %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
		return assignments
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating individual resource-level RBAC assignments for subscription %s", subID), globals.AZ_RBAC_MODULE_NAME)
	}

	// List all resources - this can be a large list
	pager := resourcesClient.NewListPager(nil)
	resourceCount := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list resources in subscription %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
			break
		}

		for _, resource := range page.Value {
			if resource.ID != nil {
				resourceCount++
				// Query role assignments for this specific resource
				resourceAssignments := m.listRoleAssignments(ctx, authClient, *resource.ID, logger)
				if len(resourceAssignments) > 0 {
					assignments = append(assignments, resourceAssignments...)
					if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
						logger.InfoM(fmt.Sprintf("Found %d role assignments on resource: %s", len(resourceAssignments), *resource.ID), globals.AZ_RBAC_MODULE_NAME)
					}
				}
			}
		}
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Scanned %d resources, found %d resource-level role assignments", resourceCount, len(assignments)), globals.AZ_RBAC_MODULE_NAME)
	}

	return assignments
}

// deduplicateAssignments removes duplicate role assignments
func (m *RBACModule) deduplicateAssignments(assignments []*armauthorization.RoleAssignment) []*armauthorization.RoleAssignment {
	seen := make(map[string]bool)
	var unique []*armauthorization.RoleAssignment

	for _, ra := range assignments {
		if ra.ID == nil {
			continue
		}

		key := *ra.ID
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ra)
		}
	}

	return unique
}

// cacheRoleDefinitions retrieves and caches all role definitions for a given scope
func (m *RBACModule) cacheRoleDefinitions(ctx context.Context, roleDefClient *armauthorization.RoleDefinitionsClient,
	scope string, logger internal.Logger) map[string]*armauthorization.RoleDefinition {

	cache := make(map[string]*armauthorization.RoleDefinition)

	pager := roleDefClient.NewListPager(scope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list role definitions for scope %s: %v", scope, err), globals.AZ_RBAC_MODULE_NAME)
			break
		}
		for _, rd := range page.Value {
			if rd != nil && rd.ID != nil {
				cache[*rd.ID] = rd
			}
		}
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Cached %d role definitions for scope %s", len(cache), scope), globals.AZ_RBAC_MODULE_NAME)
	}

	return cache
}

// buildRBACTableRows converts a role assignment to multiple table rows (one per provider) matching RBACHeader
// Returns a slice of rows, with one row per provider that the role has permissions for
func (m *RBACModule) buildRBACTableRows(ra *armauthorization.RoleAssignment, subID, subName string,
	roleDefs map[string]*armauthorization.RoleDefinition) [][]string {

	var rows [][]string

	principalID := ""
	principalType := ""
	roleName := ""
	roleDefID := ""
	scope := ""
	condition := ""
	delegatedResource := ""

	if ra.Properties != nil {
		if ra.Properties.PrincipalID != nil {
			principalID = *ra.Properties.PrincipalID
		}
		if ra.Properties.PrincipalType != nil {
			principalType = string(*ra.Properties.PrincipalType)
		}
		if ra.Properties.RoleDefinitionID != nil {
			roleDefID = *ra.Properties.RoleDefinitionID
		}
		if ra.Properties.Scope != nil {
			scope = *ra.Properties.Scope
		}
		if ra.Properties.Condition != nil {
			condition = *ra.Properties.Condition
		}
		if ra.Properties.DelegatedManagedIdentityResourceID != nil {
			delegatedResource = *ra.Properties.DelegatedManagedIdentityResourceID
		}
	}

	// Lookup role name and build provider list from role definition
	providerList := []string{}
	if roleDefID != "" {
		if rd, ok := roleDefs[roleDefID]; ok {
			if rd.Properties != nil && rd.Properties.RoleName != nil {
				roleName = *rd.Properties.RoleName
			}

			// Extract unique providers from role permissions
			providersSet := make(map[string]struct{})
			if rd.Properties != nil && rd.Properties.Permissions != nil {
				for _, perm := range rd.Properties.Permissions {
					if perm.Actions != nil {
						for _, actionPtr := range perm.Actions {
							if actionPtr != nil {
								action := *actionPtr
								if idx := strings.Index(action, "/"); idx != -1 {
									provider := action[:idx]
									providersSet[provider] = struct{}{}
								}
							}
						}
					}
				}
			}

			// Convert set to sorted slice
			for p := range providersSet {
				providerList = append(providerList, p)
			}
			sort.Strings(providerList)
		}
	}

	// If no providers found, create one row with empty provider
	if len(providerList) == 0 {
		providerList = []string{""}
	}

	// Parse scope to extract tenant/subscription/RG
	tenantScope := ""
	subscriptionScope := ""
	resourceGroupScope := ""

	if strings.HasPrefix(scope, "/subscriptions/") {
		subscriptionScope = subName
		parts := strings.Split(scope, "/")
		for i, part := range parts {
			if part == "resourceGroups" && i+1 < len(parts) {
				resourceGroupScope = parts[i+1]
				break
			}
		}
	} else if scope == "/" || strings.Contains(scope, "managementGroups") {
		tenantScope = m.TenantName
		if scope == "/" {
			subscriptionScope = "*"
			resourceGroupScope = "*"
		}
	}

	// Create one row per provider
	for _, provider := range providerList {
		row := []string{
			principalID,        // Principal GUID
			"",                 // Principal Name (would need lookup)
			"",                 // Principal UPN (would need lookup)
			principalType,      // Principal Type
			roleName,           // Role Name
			provider,           // Providers/Resources (one per row)
			"Direct",           // Assigned Via (default for backward compatibility)
			tenantScope,        // Tenant Scope
			subscriptionScope,  // Subscription Scope
			resourceGroupScope, // Resource Group Scope
			scope,              // Full Scope
			condition,          // Condition
			delegatedResource,  // Delegated Managed Identity Resource
		}
		rows = append(rows, row)
	}

	return rows
}

// buildRBACTableRowsWithMeta builds table rows with metadata including "Assigned Via" tracking and nested group resolution
func (m *RBACModule) buildRBACTableRowsWithMeta(ctx context.Context, meta rbacAssignmentWithMeta, subID, subName string,
	roleDefs map[string]*armauthorization.RoleDefinition, logger internal.Logger) [][]string {

	var rows [][]string
	ra := meta.Assignment

	principalID := ""
	principalType := ""
	roleName := ""
	roleDefID := ""
	scope := ""
	condition := ""
	delegatedResource := ""

	if ra.Properties != nil {
		if ra.Properties.PrincipalID != nil {
			principalID = *ra.Properties.PrincipalID
		}
		if ra.Properties.PrincipalType != nil {
			principalType = string(*ra.Properties.PrincipalType)
		}
		if ra.Properties.RoleDefinitionID != nil {
			roleDefID = *ra.Properties.RoleDefinitionID
		}
		if ra.Properties.Scope != nil {
			scope = *ra.Properties.Scope
		}
		if ra.Properties.Condition != nil {
			condition = *ra.Properties.Condition
		}
		if ra.Properties.DelegatedManagedIdentityResourceID != nil {
			delegatedResource = *ra.Properties.DelegatedManagedIdentityResourceID
		}
	}

	// Lookup role name and build provider list from role definition
	providerList := []string{}
	if roleDefID != "" {
		if rd, ok := roleDefs[roleDefID]; ok {
			if rd.Properties != nil && rd.Properties.RoleName != nil {
				roleName = *rd.Properties.RoleName
			}

			// Extract unique providers from role permissions
			providersSet := make(map[string]struct{})
			if rd.Properties != nil && rd.Properties.Permissions != nil {
				for _, perm := range rd.Properties.Permissions {
					if perm.Actions != nil {
						for _, actionPtr := range perm.Actions {
							if actionPtr != nil {
								action := *actionPtr
								if idx := strings.Index(action, "/"); idx != -1 {
									provider := action[:idx]
									providersSet[provider] = struct{}{}
								}
							}
						}
					}
				}
			}

			// Convert set to sorted slice
			for p := range providersSet {
				providerList = append(providerList, p)
			}
			sort.Strings(providerList)
		}
	}

	// If no providers found, create one row with empty provider
	if len(providerList) == 0 {
		providerList = []string{""}
	}

	// Parse scope to extract tenant/subscription/RG
	tenantScope := ""
	subscriptionScope := ""
	resourceGroupScope := ""

	if strings.HasPrefix(scope, "/subscriptions/") {
		subscriptionScope = subName
		parts := strings.Split(scope, "/")
		for i, part := range parts {
			if part == "resourceGroups" && i+1 < len(parts) {
				resourceGroupScope = parts[i+1]
				break
			}
		}
	} else if scope == "/" || strings.Contains(scope, "managementGroups") {
		tenantScope = m.TenantName
		if scope == "/" {
			subscriptionScope = "*"
			resourceGroupScope = "*"
		}
	}

	// Resolve nested groups if the principal is a Group
	nestedGroups := ""
	if principalType == "Group" && principalID != "" {
		nestedGroups = m.resolveNestedGroupChain(ctx, principalID, logger)
	}

	// Create one row per provider
	for _, provider := range providerList {
		row := []string{
			principalID,        // Principal GUID
			"",                 // Principal Name (would need lookup)
			"",                 // Principal UPN (would need lookup)
			principalType,      // Principal Type
			roleName,           // Role Name
			provider,           // Providers/Resources (one per row)
			meta.AssignedVia,   // Assigned Via (Direct/Group/PIM status)
			nestedGroups,       // Nested Groups (parent groups this group belongs to)
			m.TenantName,       // Tenant Name (always populated for multi-tenant support)
			m.TenantID,         // Tenant ID (always populated for multi-tenant support)
			tenantScope,        // Tenant Scope (specific to assignment scope, e.g., "/" or mgmt group)
			subscriptionScope,  // Subscription Scope
			resourceGroupScope, // Resource Group Scope
			scope,              // Full Scope
			condition,          // Condition
			delegatedResource,  // Delegated Managed Identity Resource
		}
		rows = append(rows, row)
	}

	return rows
}

// determineAssignedViaFromProperties determines the "Assigned Via" value based on assignment properties
func (m *RBACModule) determineAssignedViaFromProperties(ra *armauthorization.RoleAssignment, isPIMEligible, isPIMActive bool) string {
	// Check if principal is a group from PrincipalType
	isGroup := false
	if ra.Properties != nil && ra.Properties.PrincipalType != nil {
		principalType := string(*ra.Properties.PrincipalType)
		isGroup = (principalType == "Group")
	}

	if isPIMActive {
		if isGroup {
			return "Group (PIM Active)"
		}
		return "Direct (PIM Active)"
	}

	if isPIMEligible {
		if isGroup {
			return "Group (PIM Eligible)"
		}
		return "Direct (PIM Eligible)"
	}

	if isGroup {
		return "Group"
	}

	return "Direct"
}

// resolveNestedGroupChain resolves the nested group membership chain for a given group
// Returns a formatted string like "ParentGroup1, ParentGroup2, ParentGroup3 (nested)"
func (m *RBACModule) resolveNestedGroupChain(ctx context.Context, groupID string, logger internal.Logger) string {
	if groupID == "" {
		return ""
	}

	// Get Graph token
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for nested group resolution: %v", err), globals.AZ_RBAC_MODULE_NAME)
		}
		return ""
	}

	// Collect parent group display names
	var parentGroupNames []string
	visitedGroups := make(map[string]bool) // Prevent infinite loops

	// Use a queue to traverse parent groups (breadth-first)
	queue := []string{groupID}
	visitedGroups[groupID] = true

	for len(queue) > 0 {
		currentGroupID := queue[0]
		queue = queue[1:]

		// Get parent groups (memberOf) for current group
		memberOfURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/memberOf?$select=id,displayName", currentGroupID)

		err := azinternal.GraphAPIPagedRequest(ctx, memberOfURL, token, func(body []byte) (bool, string, error) {
			var data struct {
				Value []struct {
					ID          string `json:"id"`
					DisplayName string `json:"displayName"`
				} `json:"value"`
				NextLink string `json:"@odata.nextLink"`
			}

			if err := json.Unmarshal(body, &data); err != nil {
				return false, "", fmt.Errorf("failed to decode memberOf response: %v", err)
			}

			for _, parentGroup := range data.Value {
				if parentGroup.ID != "" && !visitedGroups[parentGroup.ID] {
					visitedGroups[parentGroup.ID] = true

					// Add display name to the list
					displayName := parentGroup.DisplayName
					if displayName == "" {
						displayName = parentGroup.ID
					}
					parentGroupNames = append(parentGroupNames, displayName)

					// Add to queue to check its parents too
					queue = append(queue, parentGroup.ID)
				}
			}

			hasMore := data.NextLink != ""
			nextURL := data.NextLink
			return hasMore, nextURL, nil
		})

		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to resolve nested groups for %s: %v", currentGroupID, err), globals.AZ_RBAC_MODULE_NAME)
			}
			break
		}
	}

	// Format the result
	if len(parentGroupNames) == 0 {
		return ""
	}

	return fmt.Sprintf("%s (nested)", strings.Join(parentGroupNames, ", "))
}

// deduplicateAssignmentsWithMeta removes duplicate assignments based on assignment ID and type
func (m *RBACModule) deduplicateAssignmentsWithMeta(assignments []rbacAssignmentWithMeta) []rbacAssignmentWithMeta {
	seen := make(map[string]bool)
	var unique []rbacAssignmentWithMeta

	for _, meta := range assignments {
		if meta.Assignment.ID == nil {
			continue
		}

		// Create unique key combining assignment ID and assigned via (to distinguish PIM from regular)
		key := fmt.Sprintf("%s|%s", *meta.Assignment.ID, meta.AssignedVia)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, meta)
		}
	}

	return unique
}

// getAllPIMEligibilitySchedules retrieves ALL PIM eligible role assignments
func (m *RBACModule) getAllPIMEligibilitySchedules(ctx context.Context, subID string, logger internal.Logger) []*armauthorization.RoleAssignment {
	var results []*armauthorization.RoleAssignment

	// Get token for ARM scope
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for PIM eligibility: %v", err), globals.AZ_RBAC_MODULE_NAME)
		return results
	}

	// Build PIM eligibility URL - NO FILTER to get ALL PIM assignments
	pimURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01", subID)

	// Fetch PIM eligibility schedules
	respBody, err := azinternal.HTTPRequestWithRetry(ctx, "GET", pimURL, token, nil, azinternal.DefaultRateLimitConfig())
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to fetch PIM eligibility schedules: %v", err), globals.AZ_RBAC_MODULE_NAME)
		}
		return results
	}

	// Parse response
	var pimResp struct {
		Value []struct {
			Properties struct {
				PrincipalID        *string `json:"principalId"`
				RoleDefinitionID   *string `json:"roleDefinitionId"`
				Scope              *string `json:"scope"`
				MemberType         *string `json:"memberType"`
				PrincipalType      *string `json:"principalType"`
				Status             *string `json:"status"`
				ExpandedProperties *struct {
					Principal *struct {
						ID   *string `json:"id"`
						Type *string `json:"type"`
					} `json:"principal"`
					RoleDefinition *struct {
						ID          *string `json:"id"`
						DisplayName *string `json:"displayName"`
					} `json:"roleDefinition"`
					Scope *struct {
						ID          *string `json:"id"`
						DisplayName *string `json:"displayName"`
						Type        *string `json:"type"`
					} `json:"scope"`
				} `json:"expandedProperties"`
			} `json:"properties"`
			ID *string `json:"id"`
		} `json:"value"`
	}

	if err := json.Unmarshal(respBody, &pimResp); err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to parse PIM eligibility response: %v", err), globals.AZ_RBAC_MODULE_NAME)
		return results
	}

	// Convert all PIM eligibility schedule instances to RoleAssignment format
	for _, item := range pimResp.Value {
		if item.Properties.PrincipalID != nil {
			ra := &armauthorization.RoleAssignment{
				ID: item.ID,
				Properties: &armauthorization.RoleAssignmentProperties{
					PrincipalID:      item.Properties.PrincipalID,
					RoleDefinitionID: item.Properties.RoleDefinitionID,
					Scope:            item.Properties.Scope,
					PrincipalType:    (*armauthorization.PrincipalType)(item.Properties.PrincipalType),
				},
			}
			results = append(results, ra)
		}
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS && len(results) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d PIM eligible assignments", len(results)), globals.AZ_RBAC_MODULE_NAME)
	}

	return results
}

// getAllPIMActiveSchedules retrieves ALL PIM active role assignments
func (m *RBACModule) getAllPIMActiveSchedules(ctx context.Context, subID string, logger internal.Logger) []*armauthorization.RoleAssignment {
	var results []*armauthorization.RoleAssignment

	// Get token for ARM scope
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for PIM active: %v", err), globals.AZ_RBAC_MODULE_NAME)
		return results
	}

	// Build PIM active URL - NO FILTER to get ALL PIM assignments
	pimURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01", subID)

	// Fetch PIM active schedules
	respBody, err := azinternal.HTTPRequestWithRetry(ctx, "GET", pimURL, token, nil, azinternal.DefaultRateLimitConfig())
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to fetch PIM active schedules: %v", err), globals.AZ_RBAC_MODULE_NAME)
		}
		return results
	}

	// Parse response
	var pimResp struct {
		Value []struct {
			Properties struct {
				PrincipalID        *string `json:"principalId"`
				RoleDefinitionID   *string `json:"roleDefinitionId"`
				Scope              *string `json:"scope"`
				MemberType         *string `json:"memberType"`
				PrincipalType      *string `json:"principalType"`
				Status             *string `json:"status"`
				ExpandedProperties *struct {
					Principal *struct {
						ID   *string `json:"id"`
						Type *string `json:"type"`
					} `json:"principal"`
					RoleDefinition *struct {
						ID          *string `json:"id"`
						DisplayName *string `json:"displayName"`
					} `json:"roleDefinition"`
					Scope *struct {
						ID          *string `json:"id"`
						DisplayName *string `json:"displayName"`
						Type        *string `json:"type"`
					} `json:"scope"`
				} `json:"expandedProperties"`
			} `json:"properties"`
			ID *string `json:"id"`
		} `json:"value"`
	}

	if err := json.Unmarshal(respBody, &pimResp); err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to parse PIM active response: %v", err), globals.AZ_RBAC_MODULE_NAME)
		return results
	}

	// Convert all PIM active schedule instances to RoleAssignment format
	for _, item := range pimResp.Value {
		if item.Properties.PrincipalID != nil {
			ra := &armauthorization.RoleAssignment{
				ID: item.ID,
				Properties: &armauthorization.RoleAssignmentProperties{
					PrincipalID:      item.Properties.PrincipalID,
					RoleDefinitionID: item.Properties.RoleDefinitionID,
					Scope:            item.Properties.Scope,
					PrincipalType:    (*armauthorization.PrincipalType)(item.Properties.PrincipalType),
				},
			}
			results = append(results, ra)
		}
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS && len(results) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d PIM active assignments", len(results)), globals.AZ_RBAC_MODULE_NAME)
	}

	return results
}

// ======================
// writeOutput - Write all collected RBAC data using HandleOutputSmart
// ======================
func (m *RBACModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.RBACRows) == 0 {
		logger.InfoM("No RBAC assignments found", globals.AZ_RBAC_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Dataset size: %d rows", len(m.RBACRows)), "output")

	// Sort by tenant, then subscription, then principal ID
	sort.Slice(m.RBACRows, func(i, j int) bool {
		// Column 8: Tenant Name
		if m.RBACRows[i][8] != m.RBACRows[j][8] {
			return m.RBACRows[i][8] < m.RBACRows[j][8]
		}
		// Column 11: Subscription Scope
		if m.RBACRows[i][11] != m.RBACRows[j][11] {
			return m.RBACRows[i][11] < m.RBACRows[j][11]
		}
		// Column 0: Principal GUID
		return m.RBACRows[i][0] < m.RBACRows[j][0]
	})

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		// Column 8 contains tenant name
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.RBACRows,
			RBACHeader,
			"rbac",
			globals.AZ_RBAC_MODULE_NAME,
		); err != nil {
			// Error already logged in helper
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		// Split into separate subscription directories
		// Column 11 contains subscription name (updated from 7 due to new tenant columns)
		if err := m.FilterAndWritePerSubscription(
			ctx,
			logger,
			m.Subscriptions,
			m.RBACRows,
			11, // Column index for "Subscription Scope" (was 7, now 11 after adding tenant columns)
			RBACHeader,
			"rbac",
			globals.AZ_RBAC_MODULE_NAME,
		); err != nil {
			// Error already logged in helper
			return
		}
		return
	}

	// Otherwise: consolidated output (single subscription OR multiple with --tenant flag)
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
		m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Generate loot files
	lootFiles := m.generateRBACLootFiles()

	// Prepare output (single file with all data, matching enterprise-apps pattern)
	output := RBACOutput{
		Table: []internal.TableFile{
			{
				Name:   "rbac",
				Header: RBACHeader,
				Body:   m.RBACRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// ------------------------------
// Loot file generation
// ------------------------------

// generateRBACLootFiles creates all RBAC loot files
func (m *RBACModule) generateRBACLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile

	// High-privilege roles loot
	if highPrivLoot := m.generateHighPrivilegeRolesLoot(); highPrivLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "rbac-high-privilege-roles",
			Contents: highPrivLoot,
		})
	}

	// Service principals with roles
	if spLoot := m.generateServicePrincipalsLoot(); spLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "rbac-service-principals",
			Contents: spLoot,
		})
	}

	// RBAC enumeration commands
	if cmdLoot := m.generateRBACCommandsLoot(); cmdLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "rbac-enumeration-commands",
			Contents: cmdLoot,
		})
	}

	// Privilege escalation paths
	if escalationLoot := m.generatePrivilegeEscalationLoot(); escalationLoot != "" {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "rbac-privilege-escalation",
			Contents: escalationLoot,
		})
	}

	return lootFiles
}

// generateHighPrivilegeRolesLoot generates loot for high-privilege role assignments
func (m *RBACModule) generateHighPrivilegeRolesLoot() string {
	var loot strings.Builder

	// Define high-privilege roles
	highPrivRoles := map[string]string{
		"Owner":                          "Full control over all resources and ability to delegate access",
		"Contributor":                    "Can create and manage all types of resources but cannot grant access",
		"User Access Administrator":      "Can manage user access to Azure resources",
		"Role Based Access Control Administrator": "Can manage role assignments",
		"Security Admin":                 "Can manage security policies and view security data",
		"Privileged Role Administrator":  "Can manage role assignments in Azure AD and PIM",
		"Global Administrator":           "Full access to all Azure AD and Azure resources",
	}

	loot.WriteString("# High-Privilege RBAC Role Assignments\n")
	loot.WriteString("# These principals have elevated permissions that could be abused for privilege escalation\n\n")

	foundHighPriv := false
	for _, row := range m.RBACRows {
		roleName := row[4]  // Column 4: Role Name
		principalType := row[3]  // Column 3: Principal Type

		// Check if this is a high-privilege role
		if risk, isHighPriv := highPrivRoles[roleName]; isHighPriv {
			foundHighPriv = true

			principalGUID := row[0]
			principalName := row[1]
			principalUPN := row[2]
			fullScope := row[13]
			tenantName := row[8]
			subscriptionScope := row[11]

			loot.WriteString(fmt.Sprintf("## %s\n", roleName))
			loot.WriteString(fmt.Sprintf("Risk: %s\n", risk))
			loot.WriteString(fmt.Sprintf("Principal: %s (%s)\n", principalName, principalType))
			loot.WriteString(fmt.Sprintf("Principal GUID: %s\n", principalGUID))
			if principalUPN != "N/A" {
				loot.WriteString(fmt.Sprintf("UPN/App ID: %s\n", principalUPN))
			}
			loot.WriteString(fmt.Sprintf("Tenant: %s\n", tenantName))
			if subscriptionScope != "N/A" {
				loot.WriteString(fmt.Sprintf("Subscription: %s\n", subscriptionScope))
			}
			loot.WriteString(fmt.Sprintf("Scope: %s\n", fullScope))
			loot.WriteString("\nCommands to investigate:\n")
			loot.WriteString(fmt.Sprintf("az role assignment list --assignee %s\n", principalGUID))
			loot.WriteString(fmt.Sprintf("az ad user show --id %s  # If user\n", principalGUID))
			loot.WriteString(fmt.Sprintf("az ad sp show --id %s   # If service principal\n", principalGUID))
			loot.WriteString("\n---\n\n")
		}
	}

	if !foundHighPriv {
		return ""
	}

	return loot.String()
}

// generateServicePrincipalsLoot generates loot for service principals with role assignments
func (m *RBACModule) generateServicePrincipalsLoot() string {
	var loot strings.Builder

	loot.WriteString("# Service Principals with RBAC Role Assignments\n")
	loot.WriteString("# Service principals are application identities that can be compromised\n")
	loot.WriteString("# Focus on: secrets/certificates, federated credentials, and managed identities\n\n")

	foundSP := false
	spMap := make(map[string][]string) // Map of SP GUID to roles

	for _, row := range m.RBACRows {
		principalType := row[3]  // Column 3: Principal Type

		if principalType == "ServicePrincipal" || principalType == "Application" {
			foundSP = true
			principalGUID := row[0]
			roleName := row[4]

			spMap[principalGUID] = append(spMap[principalGUID], roleName)
		}
	}

	if !foundSP {
		return ""
	}

	// Generate loot for each SP
	for _, row := range m.RBACRows {
		principalType := row[3]

		if principalType == "ServicePrincipal" || principalType == "Application" {
			principalGUID := row[0]
			principalName := row[1]
			principalAppID := row[2]
			roleName := row[4]
			fullScope := row[13]
			tenantName := row[8]

			loot.WriteString(fmt.Sprintf("## Service Principal: %s\n", principalName))
			loot.WriteString(fmt.Sprintf("Application ID: %s\n", principalAppID))
			loot.WriteString(fmt.Sprintf("Object ID: %s\n", principalGUID))
			loot.WriteString(fmt.Sprintf("Tenant: %s\n", tenantName))
			loot.WriteString(fmt.Sprintf("Role: %s\n", roleName))
			loot.WriteString(fmt.Sprintf("Scope: %s\n", fullScope))
			loot.WriteString("\nEnumeration commands:\n")
			loot.WriteString(fmt.Sprintf("# Get service principal details\n"))
			loot.WriteString(fmt.Sprintf("az ad sp show --id %s\n\n", principalGUID))
			loot.WriteString(fmt.Sprintf("# Check for credentials (secrets/certificates)\n"))
			loot.WriteString(fmt.Sprintf("az ad app credential list --id %s\n\n", principalAppID))
			loot.WriteString(fmt.Sprintf("# Check for federated credentials (OIDC/GitHub Actions)\n"))
			loot.WriteString(fmt.Sprintf("az ad app federated-credential list --id %s\n\n", principalAppID))
			loot.WriteString(fmt.Sprintf("# List all roles for this service principal\n"))
			loot.WriteString(fmt.Sprintf("az role assignment list --assignee %s --all\n", principalGUID))
			loot.WriteString("\n---\n\n")

			// Only output once per SP
			break
		}
	}

	return loot.String()
}

// generateRBACCommandsLoot generates commands for further RBAC enumeration
func (m *RBACModule) generateRBACCommandsLoot() string {
	var loot strings.Builder

	loot.WriteString("# RBAC Enumeration Commands\n")
	loot.WriteString("# Use these commands to enumerate RBAC permissions and identify privilege escalation opportunities\n\n")

	// Collect unique tenants and subscriptions
	tenantsMap := make(map[string]string)
	subscriptionsMap := make(map[string]bool)

	for _, row := range m.RBACRows {
		tenantID := row[9]
		tenantName := row[8]
		subscriptionScope := row[11]

		if tenantID != "N/A" {
			tenantsMap[tenantID] = tenantName
		}
		if subscriptionScope != "N/A" {
			subscriptionsMap[subscriptionScope] = true
		}
	}

	// Generate commands for each tenant
	for tenantID, tenantName := range tenantsMap {
		loot.WriteString(fmt.Sprintf("## Tenant: %s (%s)\n\n", tenantName, tenantID))

		loot.WriteString("# List all role assignments\n")
		loot.WriteString("az role assignment list --all\n\n")

		loot.WriteString("# List role assignments for specific high-privilege roles\n")
		loot.WriteString("az role assignment list --role \"Owner\" --all\n")
		loot.WriteString("az role assignment list --role \"Contributor\" --all\n")
		loot.WriteString("az role assignment list --role \"User Access Administrator\" --all\n\n")

		loot.WriteString("# List custom role definitions (may have dangerous permissions)\n")
		loot.WriteString("az role definition list --custom-role-only true\n\n")

		loot.WriteString("# Check PIM (Privileged Identity Management) eligible assignments\n")
		loot.WriteString("az rest --method GET --url \"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01\"\n\n")

		loot.WriteString("# Check PIM active assignments\n")
		loot.WriteString("az rest --method GET --url \"https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01\"\n\n")
	}

	// Generate commands for each subscription
	if len(subscriptionsMap) > 0 {
		loot.WriteString("## Per-Subscription Enumeration\n\n")
		for subscription := range subscriptionsMap {
			loot.WriteString(fmt.Sprintf("# Subscription: %s\n", subscription))
			loot.WriteString(fmt.Sprintf("az account set --subscription \"%s\"\n", subscription))
			loot.WriteString("az role assignment list --all\n\n")
		}
	}

	loot.WriteString("## Enumerate your own permissions\n")
	loot.WriteString("# Check what actions you can perform\n")
	loot.WriteString("az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv)\n\n")

	loot.WriteString("# List your effective permissions\n")
	loot.WriteString("az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) --all\n\n")

	return loot.String()
}

// generatePrivilegeEscalationLoot generates privilege escalation guidance
func (m *RBACModule) generatePrivilegeEscalationLoot() string {
	var loot strings.Builder

	loot.WriteString("# RBAC Privilege Escalation Paths\n")
	loot.WriteString("# Common privilege escalation techniques using RBAC permissions\n\n")

	// Track which escalation paths are relevant based on roles found
	foundRoles := make(map[string]bool)
	for _, row := range m.RBACRows {
		roleName := row[4]
		foundRoles[roleName] = true
	}

	// Contributor escalation
	if foundRoles["Contributor"] {
		loot.WriteString("## Contributor Role → Owner\n")
		loot.WriteString("Risk: Contributor can deploy ARM templates with managed identities that have higher privileges\n\n")
		loot.WriteString("### Method 1: Deploy VM with managed identity\n")
		loot.WriteString("1. Create a user-assigned managed identity with Owner role (if you have permissions)\n")
		loot.WriteString("2. Deploy a VM with that managed identity attached\n")
		loot.WriteString("3. Access the VM and use the managed identity to escalate privileges\n\n")
		loot.WriteString("Commands:\n")
		loot.WriteString("az identity create --name escalation-identity --resource-group <rg>\n")
		loot.WriteString("az vm create --name escalation-vm --resource-group <rg> --assign-identity <identity-id>\n")
		loot.WriteString("# SSH into VM, then:\n")
		loot.WriteString("az login --identity\n")
		loot.WriteString("az role assignment create --assignee <identity-id> --role Owner --scope <scope>\n\n")

		loot.WriteString("### Method 2: Modify existing resource with managed identity\n")
		loot.WriteString("1. Find existing resources with managed identities that have higher privileges\n")
		loot.WriteString("2. Modify the resource to execute commands (run-command, custom script extension)\n")
		loot.WriteString("3. Use the managed identity to escalate\n\n")
		loot.WriteString("---\n\n")
	}

	// Virtual Machine Contributor escalation
	if foundRoles["Virtual Machine Contributor"] {
		loot.WriteString("## Virtual Machine Contributor → Code Execution\n")
		loot.WriteString("Risk: Can execute arbitrary code on VMs using run-command\n\n")
		loot.WriteString("Commands:\n")
		loot.WriteString("# List all VMs\n")
		loot.WriteString("az vm list --query '[].{Name:name, RG:resourceGroup}' -o table\n\n")
		loot.WriteString("# Execute command on VM\n")
		loot.WriteString("az vm run-command invoke --resource-group <rg> --name <vm> --command-id RunShellScript --scripts \"whoami; cat /etc/shadow\"\n\n")
		loot.WriteString("# Or for Windows:\n")
		loot.WriteString("az vm run-command invoke --resource-group <rg> --name <vm> --command-id RunPowerShellScript --scripts \"whoami; Get-ChildItem Env:\"\n\n")
		loot.WriteString("---\n\n")
	}

	// User Access Administrator escalation
	if foundRoles["User Access Administrator"] {
		loot.WriteString("## User Access Administrator → Full Control\n")
		loot.WriteString("Risk: Can assign any role to any principal, including Owner to yourself\n\n")
		loot.WriteString("Commands:\n")
		loot.WriteString("# Grant yourself Owner role\n")
		loot.WriteString("az role assignment create --assignee $(az ad signed-in-user show --query id -o tsv) --role Owner --scope /subscriptions/<subscription-id>\n\n")
		loot.WriteString("# Or grant to a service principal you control\n")
		loot.WriteString("az role assignment create --assignee <sp-object-id> --role Owner --scope <scope>\n\n")
		loot.WriteString("---\n\n")
	}

	// Key Vault-related roles
	if foundRoles["Key Vault Contributor"] || foundRoles["Key Vault Administrator"] {
		loot.WriteString("## Key Vault Permissions → Secret Access\n")
		loot.WriteString("Risk: Can modify access policies to grant yourself secret read permissions\n\n")
		loot.WriteString("Commands:\n")
		loot.WriteString("# List Key Vaults\n")
		loot.WriteString("az keyvault list\n\n")
		loot.WriteString("# Grant yourself secret permissions\n")
		loot.WriteString("az keyvault set-policy --name <vault-name> --upn <your-upn> --secret-permissions get list\n\n")
		loot.WriteString("# List and extract secrets\n")
		loot.WriteString("az keyvault secret list --vault-name <vault-name>\n")
		loot.WriteString("az keyvault secret show --vault-name <vault-name> --name <secret-name>\n\n")
		loot.WriteString("---\n\n")
	}

	// Automation Account Contributor
	if foundRoles["Automation Contributor"] {
		loot.WriteString("## Automation Contributor → Credential Harvesting\n")
		loot.WriteString("Risk: Can create/modify runbooks to execute code with high privileges\n\n")
		loot.WriteString("Commands:\n")
		loot.WriteString("# List automation accounts\n")
		loot.WriteString("az automation account list\n\n")
		loot.WriteString("# Create a runbook that extracts credentials\n")
		loot.WriteString("az automation runbook create --automation-account-name <account> --resource-group <rg> --name extract-creds --type PowerShell\n\n")
		loot.WriteString("# Publish and run the runbook\n")
		loot.WriteString("az automation runbook publish --automation-account-name <account> --resource-group <rg> --name extract-creds\n")
		loot.WriteString("az automation runbook start --automation-account-name <account> --resource-group <rg> --name extract-creds\n\n")
		loot.WriteString("---\n\n")
	}

	// Website Contributor
	if foundRoles["Website Contributor"] || foundRoles["Web Plan Contributor"] {
		loot.WriteString("## Website Contributor → Configuration Access\n")
		loot.WriteString("Risk: Can access App Service configuration containing connection strings and secrets\n\n")
		loot.WriteString("Commands:\n")
		loot.WriteString("# List web apps\n")
		loot.WriteString("az webapp list\n\n")
		loot.WriteString("# Get app settings (may contain secrets)\n")
		loot.WriteString("az webapp config appsettings list --name <app-name> --resource-group <rg>\n\n")
		loot.WriteString("# Get connection strings\n")
		loot.WriteString("az webapp config connection-string list --name <app-name> --resource-group <rg>\n\n")
		loot.WriteString("# Download source code via Kudu\n")
		loot.WriteString("az webapp deployment source config-zip --name <app-name> --resource-group <rg> --src <path-to-zip>\n\n")
		loot.WriteString("---\n\n")
	}

	// Storage Account Contributor/Key Operator
	if foundRoles["Storage Account Contributor"] || foundRoles["Storage Account Key Operator Service Role"] {
		loot.WriteString("## Storage Account Permissions → Key Access\n")
		loot.WriteString("Risk: Can list storage account keys and access all data\n\n")
		loot.WriteString("Commands:\n")
		loot.WriteString("# List storage accounts\n")
		loot.WriteString("az storage account list\n\n")
		loot.WriteString("# Get storage account keys\n")
		loot.WriteString("az storage account keys list --account-name <account> --resource-group <rg>\n\n")
		loot.WriteString("# Use keys to access blobs\n")
		loot.WriteString("az storage blob list --account-name <account> --container-name <container> --account-key <key>\n")
		loot.WriteString("az storage blob download-batch --account-name <account> --source <container> --destination ./downloaded --account-key <key>\n\n")
		loot.WriteString("---\n\n")
	}

	if len(foundRoles) == 0 {
		return ""
	}

	loot.WriteString("## General Privilege Escalation Tips\n\n")
	loot.WriteString("1. Look for custom roles with dangerous action combinations\n")
	loot.WriteString("2. Check for orphaned role assignments (deleted principals that can be recreated)\n")
	loot.WriteString("3. Identify service principals with secrets vs. certificate auth\n")
	loot.WriteString("4. Look for managed identities on resources you can access\n")
	loot.WriteString("5. Check for PIM eligible assignments you can activate\n")
	loot.WriteString("6. Look for role assignments at management group or tenant root scope\n")
	loot.WriteString("7. Identify principals with write permissions on role assignments\n\n")

	return loot.String()
}
