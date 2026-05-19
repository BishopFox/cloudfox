package commands

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
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

// rbacRowInput holds cache-native fields for building table rows directly,
// avoiding round-trip conversion through *armauthorization.RoleAssignment.
type rbacRowInput struct {
	PrincipalID      string
	PrincipalType    string
	RoleDefinitionID string
	RoleName         string // pre-resolved from cache (or role defs map for resource-level)
	Scope            string
	Condition        string
	DelegatedMI      string
	AssignedVia      string
	IsPIM            bool
	IsPIMActive      bool
}

// RBACModule implements RBAC enumeration using BaseAzureModule pattern
type RBACModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	TenantLevel   bool
	SubLevel      bool
	RGLevel       bool
	NoDedupe      bool
	roleDefs      map[string]*armauthorization.RoleDefinition // Populated once in prefetch

	// Disk-backed row storage (avoids OOM on large tenants)
	rbacRowFile  *os.File // temp CSV file holding all RBAC rows
	rbacRowCount int      // number of rows written
}

var (
	noDedupe       bool
	runTenantLevel bool
	runSubLevel    bool
	runRGLevel     bool
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

// openRBACRowFile creates a temp CSV file for streaming RBAC rows to disk.
func (m *RBACModule) openRBACRowFile() error {
	f, err := os.CreateTemp("", "cloudfox-rbac-*.csv")
	if err != nil {
		return fmt.Errorf("failed to create temp row file: %w", err)
	}
	m.rbacRowFile = f
	m.rbacRowCount = 0
	return nil
}

// writeRBACRows writes a batch of rows to the temp CSV file.
func (m *RBACModule) writeRBACRows(rows [][]string) {
	if m.rbacRowFile == nil || len(rows) == 0 {
		return
	}
	w := csv.NewWriter(m.rbacRowFile)
	for _, row := range rows {
		_ = w.Write(row)
	}
	w.Flush()
	m.rbacRowCount += len(rows)
}

// closeRBACRowFile closes the temp CSV file.
func (m *RBACModule) closeRBACRowFile() {
	if m.rbacRowFile != nil {
		m.rbacRowFile.Close()
	}
}

// removeRBACRowFile deletes the temp CSV file.
func (m *RBACModule) removeRBACRowFile() {
	if m.rbacRowFile != nil {
		os.Remove(m.rbacRowFile.Name())
	}
}

// iterateRBACRows streams through all rows in the temp file, calling fn for each row.
func (m *RBACModule) iterateRBACRows(fn func(row []string)) error {
	if m.rbacRowFile == nil {
		return nil
	}
	if _, err := m.rbacRowFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek temp row file: %w", err)
	}
	r := csv.NewReader(bufio.NewReaderSize(m.rbacRowFile, 256*1024))
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		fn(row)
	}
	return nil
}

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

	// Parse RBAC-specific flags
	tenantLevel, _ := cmd.Flags().GetBool("tenant-level")
	subLevel, _ := cmd.Flags().GetBool("subscription-level")
	rgLevel, _ := cmd.Flags().GetBool("resource-group-level")
	noDedupe, _ := cmd.Flags().GetBool("no-dedupe")

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
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 0),
		Subscriptions:   cmdCtx.Subscriptions,
		TenantLevel:     tenantLevel,
		SubLevel:        subLevel,
		RGLevel:         rgLevel,
		NoDedupe:        noDedupe,
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

	// Open temp file for streaming rows to disk
	if err := m.openRBACRowFile(); err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to open temp row file: %v", err), globals.AZ_RBAC_MODULE_NAME)
		return
	}
	defer m.removeRBACRowFile()
	defer m.closeRBACRowFile()

	// ── Phase 1: DOWNLOAD (bulk pre-fetch all data into caches) ──
	m.prefetchAllData(ctx, logger)

	// ── Phase 2: BUILD ROWS (pure cache reads, zero API calls except resource-level) ──
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo
			savedSubs := m.Subscriptions

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo
			m.Subscriptions = tenantCtx.Subscriptions

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_RBAC_MODULE_NAME)
			}

			m.buildAllRBACRows(ctx, logger)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
			m.Subscriptions = savedSubs
		}
	} else {
		m.buildAllRBACRows(ctx, logger)
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
// prefetchAllData - Phase 1: Bulk pre-fetch all data into caches
// ======================
func (m *RBACModule) prefetchAllData(ctx context.Context, logger internal.Logger) {
	spinner := internal.NewPhaseSpinner(globals.AZ_RBAC_MODULE_NAME)

	// Limit concurrent subscription prefetches to avoid thundering herd against ARM API.
	// The AIMD rate limiter gates individual requests, but unbounded goroutines still
	// cause excessive token refreshes, connection churn, and memory pressure.
	subSem := make(chan struct{}, 5)

	// Load group memberships (API + disk cache, needed for nested group chain resolution)
	spinner.Add("group memberships")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer spinner.Done("group memberships")
		azinternal.PreFetchGroupMemberships(ctx, m.Session, m.OutputDirectory, m.TenantID)
	}()

	// Pre-fetch RBAC assignments per subscription (populates scope-level caches)
	for _, subID := range m.Subscriptions {
		spinner.Add("RBAC assignments")
		wg.Add(1)
		go func(sid string) {
			defer wg.Done()
			subSem <- struct{}{}
			defer func() { <-subSem }()
			defer spinner.Done("RBAC assignments")
			azinternal.PreFetchRBACAssignmentsForSubscription(ctx, m.Session, sid, m.OutputDirectory, m.TenantID)
		}(subID)

		spinner.Add("PIM roles")
		wg.Add(1)
		go func(sid string) {
			defer wg.Done()
			subSem <- struct{}{}
			defer func() { <-subSem }()
			defer spinner.Done("PIM roles")
			azinternal.PreFetchPIMRolesForSubscription(ctx, m.Session, sid, m.OutputDirectory, m.TenantID)
		}(subID)
	}

	// Pre-fetch RBAC at resource group scopes (only if RG-level enabled)
	if m.RGLevel {
		for _, subID := range m.Subscriptions {
			spinner.Add("RG RBAC assignments")
			wg.Add(1)
			go func(sid string) {
				defer wg.Done()
				subSem <- struct{}{}
				defer func() { <-subSem }()
				defer spinner.Done("RG RBAC assignments")
				azinternal.PreFetchRBACAssignmentsForResourceGroups(ctx, m.Session, sid)
			}(subID)
		}
	}

	wg.Wait()
	spinner.Stop("Pre-fetching RBAC data: done")

	// Collect role definitions once (needed only for resource-level API assignments).
	// Cached RBAC entries already have RoleName pre-resolved.
	if m.RGLevel && len(m.Subscriptions) > 0 {
		m.collectRoleDefinitions(ctx, logger)
	}
}

// collectRoleDefinitions fetches role definitions from the first subscription and
// caches them in m.roleDefs. Called once before any row building.
func (m *RBACModule) collectRoleDefinitions(ctx context.Context, logger internal.Logger) {
	m.roleDefs = make(map[string]*armauthorization.RoleDefinition)

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for role definitions: %v", err), globals.AZ_RBAC_MODULE_NAME)
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	subScope := fmt.Sprintf("/subscriptions/%s", m.Subscriptions[0])

	clientFactory, err := armauthorization.NewClientFactory(m.Subscriptions[0], cred, azinternal.DefaultARMClientOptions())
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create client factory for role definitions: %v", err), globals.AZ_RBAC_MODULE_NAME)
		return
	}

	roleDefClient := clientFactory.NewRoleDefinitionsClient()
	pager := roleDefClient.NewListPager(subScope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list role definitions: %v", err), globals.AZ_RBAC_MODULE_NAME)
			break
		}
		for _, rd := range page.Value {
			if rd != nil && rd.ID != nil {
				m.roleDefs[*rd.ID] = rd
			}
		}
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Cached %d role definitions", len(m.roleDefs)), globals.AZ_RBAC_MODULE_NAME)
	}
}

// ======================
// buildAllRBACRows - Phase 2: Build rows from caches (zero API calls except resource-level)
// ======================
func (m *RBACModule) buildAllRBACRows(ctx context.Context, logger internal.Logger) {
	for _, subID := range m.Subscriptions {
		subName := ""
		for _, s := range m.TenantInfo.Subscriptions {
			if s.ID == subID {
				subName = s.Name
				break
			}
		}

		var allInputs []rbacRowInput

		// --- Build scope list from caches ---
		var scopes []string

		// 1. Tenant root "/" (if tenant-level requested)
		if m.TenantLevel {
			scopes = append(scopes, "/")
		}

		// 2. Management group hierarchy (already cached by PreFetchRBACAssignmentsForSubscription)
		mgHierarchy := azinternal.GetManagementGroupHierarchy(ctx, m.Session, subID)
		if m.TenantLevel {
			for _, mgID := range mgHierarchy {
				scopes = append(scopes, fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID))
			}
		}

		// 3. Subscription scope
		if m.SubLevel {
			scopes = append(scopes, fmt.Sprintf("/subscriptions/%s", subID))
		}

		// 4. Resource group scopes (discovered from cache keys, not API)
		if m.RGLevel {
			prefix := azinternal.AzCacheKey("rbac-scope-all", fmt.Sprintf("/subscriptions/%s/resourceGroups/", subID))
			for key := range azinternal.AzureDataCache.Items() {
				if strings.HasPrefix(key, prefix) {
					scopePath := strings.TrimPrefix(key, "az-rbac-scope-all-")
					scopes = append(scopes, scopePath)
				}
			}
		}

		// --- Iterate scopes and build inputs from cache ---
		for _, scope := range scopes {
			entries := azinternal.ListAllRBACForScope(scope)
			for _, e := range entries {
				allInputs = append(allInputs, rbacRowInput{
					PrincipalID:      e.PrincipalID,
					PrincipalType:    e.PrincipalType,
					RoleDefinitionID: e.RoleDefinitionID,
					RoleName:         e.RoleName,
					Scope:            e.Scope,
					Condition:        e.Condition,
					DelegatedMI:      e.DelegatedManagedIdentityResourceID,
					AssignedVia:      assignedViaFromType(e.PrincipalType, false, false),
				})
			}
		}

		// --- PIM from cache ---
		pimEligible, pimActive, _ := azinternal.ListAllPIMForSubscription(subID)
		for _, pa := range pimEligible {
			allInputs = append(allInputs, rbacRowInput{
				PrincipalID:      pa.PrincipalID,
				PrincipalType:    pa.PrincipalType,
				RoleDefinitionID: pa.RoleDefinitionID,
				RoleName:         pa.RoleName,
				Scope:            pa.Scope,
				AssignedVia:      assignedViaFromType(pa.PrincipalType, true, false),
				IsPIM:            true,
			})
		}
		for _, pa := range pimActive {
			allInputs = append(allInputs, rbacRowInput{
				PrincipalID:      pa.PrincipalID,
				PrincipalType:    pa.PrincipalType,
				RoleDefinitionID: pa.RoleDefinitionID,
				RoleName:         pa.RoleName,
				Scope:            pa.Scope,
				AssignedVia:      assignedViaFromType(pa.PrincipalType, false, true),
				IsPIM:            true,
				IsPIMActive:      true,
			})
		}

		// --- Resource-level assignments (API, unavoidable) ---
		if m.RGLevel {
			resourceInputs := m.fetchResourceLevelInputs(ctx, subID, logger)
			allInputs = append(allInputs, resourceInputs...)
		}

		// Deduplicate
		if !m.NoDedupe {
			allInputs = deduplicateInputs(allInputs)
		}

		// Build rows and stream to disk
		for _, input := range allInputs {
			rows := m.buildRowsFromInput(ctx, input, subID, subName, logger)
			m.writeRBACRows(rows)
		}

		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Collected %d RBAC assignments from %s", len(allInputs), subID), globals.AZ_RBAC_MODULE_NAME)
		}
	}
}

// assignedViaFromType determines the "Assigned Via" value from principal type and PIM flags.
func assignedViaFromType(principalType string, isPIMEligible, isPIMActive bool) string {
	isGroup := strings.EqualFold(principalType, "Group")
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

// fetchResourceLevelInputs queries resource-level RBAC via API and converts to rbacRowInput.
// This is the one remaining API path that cannot be cached.
func (m *RBACModule) fetchResourceLevelInputs(ctx context.Context, subID string, logger internal.Logger) []rbacRowInput {
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for resource-level RBAC in %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
		return nil
	}

	cred := &azinternal.StaticTokenCredential{Token: token}

	clientFactory, err := armauthorization.NewClientFactory(subID, cred, azinternal.DefaultARMClientOptions())
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create auth client for resource-level RBAC in %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
		return nil
	}

	authClient := clientFactory.NewRoleAssignmentsClient()
	apiAssignments := m.listResourceLevelAssignments(ctx, subID, authClient, cred, logger)

	var inputs []rbacRowInput
	for _, ra := range apiAssignments {
		if ra.Properties == nil {
			continue
		}
		input := rbacRowInput{}
		if ra.Properties.PrincipalID != nil {
			input.PrincipalID = *ra.Properties.PrincipalID
		}
		if ra.Properties.PrincipalType != nil {
			input.PrincipalType = string(*ra.Properties.PrincipalType)
		}
		if ra.Properties.RoleDefinitionID != nil {
			input.RoleDefinitionID = *ra.Properties.RoleDefinitionID
			// Resolve role name from pre-fetched role definitions
			if m.roleDefs != nil {
				if rd, ok := m.roleDefs[*ra.Properties.RoleDefinitionID]; ok && rd.Properties != nil && rd.Properties.RoleName != nil {
					input.RoleName = *rd.Properties.RoleName
				}
			}
		}
		if ra.Properties.Scope != nil {
			input.Scope = *ra.Properties.Scope
		}
		if ra.Properties.Condition != nil {
			input.Condition = *ra.Properties.Condition
		}
		if ra.Properties.DelegatedManagedIdentityResourceID != nil {
			input.DelegatedMI = *ra.Properties.DelegatedManagedIdentityResourceID
		}
		input.AssignedVia = assignedViaFromType(input.PrincipalType, false, false)
		inputs = append(inputs, input)
	}
	return inputs
}

// deduplicateInputs removes duplicate rbacRowInput entries based on a composite key.
func deduplicateInputs(inputs []rbacRowInput) []rbacRowInput {
	seen := make(map[string]bool)
	var unique []rbacRowInput
	for _, input := range inputs {
		key := fmt.Sprintf("%s|%s|%s|%s", input.PrincipalID, input.RoleDefinitionID, input.Scope, input.AssignedVia)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, input)
		}
	}
	return unique
}

// buildRowsFromInput builds table rows directly from an rbacRowInput (no intermediate API types).
func (m *RBACModule) buildRowsFromInput(ctx context.Context, input rbacRowInput, subID, subName string, logger internal.Logger) [][]string {
	var rows [][]string

	// Build provider list from role definition (if we have it cached)
	providerList := m.extractProviders(input.RoleDefinitionID)
	if len(providerList) == 0 {
		providerList = []string{""}
	}

	// Parse scope to extract tenant/subscription/RG
	tenantScope := ""
	subscriptionScope := ""
	resourceGroupScope := ""

	if strings.HasPrefix(input.Scope, "/subscriptions/") {
		subscriptionScope = subName
		parts := strings.Split(input.Scope, "/")
		for i, part := range parts {
			if part == "resourceGroups" && i+1 < len(parts) {
				resourceGroupScope = parts[i+1]
				break
			}
		}
	} else if input.Scope == "/" || strings.Contains(input.Scope, "managementGroups") {
		tenantScope = m.TenantName
		if input.Scope == "/" {
			subscriptionScope = "*"
			resourceGroupScope = "*"
		}
	}

	// Resolve nested groups if the principal is a Group
	nestedGroups := ""
	if input.PrincipalType == "Group" && input.PrincipalID != "" {
		nestedGroups = m.resolveNestedGroupChain(ctx, input.PrincipalID, logger)
	}

	// Create one row per provider
	for _, provider := range providerList {
		row := []string{
			input.PrincipalID,   // Principal GUID
			"",                  // Principal Name (would need lookup)
			"",                  // Principal UPN (would need lookup)
			input.PrincipalType, // Principal Type
			input.RoleName,      // Role Name
			provider,            // Providers/Resources (one per row)
			input.AssignedVia,   // Assigned Via
			nestedGroups,        // Nested Groups
			m.TenantName,        // Tenant Name
			m.TenantID,          // Tenant ID
			tenantScope,         // Tenant Scope
			subscriptionScope,   // Subscription Scope
			resourceGroupScope,  // Resource Group Scope
			input.Scope,         // Full Scope
			input.Condition,     // Condition
			input.DelegatedMI,   // Delegated Managed Identity Resource
		}
		rows = append(rows, row)
	}

	return rows
}

// extractProviders extracts unique provider names from a role definition.
// Uses the pre-fetched roleDefs map (for resource-level) or returns empty for cached entries
// where the role name is already resolved.
func (m *RBACModule) extractProviders(roleDefID string) []string {
	if roleDefID == "" || m.roleDefs == nil {
		return nil
	}
	rd, ok := m.roleDefs[roleDefID]
	if !ok || rd.Properties == nil || rd.Properties.Permissions == nil {
		return nil
	}

	providersSet := make(map[string]struct{})
	for _, perm := range rd.Properties.Permissions {
		if perm.Actions != nil {
			for _, actionPtr := range perm.Actions {
				if actionPtr != nil {
					action := *actionPtr
					if idx := strings.Index(action, "/"); idx != -1 {
						providersSet[action[:idx]] = struct{}{}
					}
				}
			}
		}
	}

	var providerList []string
	for p := range providersSet {
		providerList = append(providerList, p)
	}
	sort.Strings(providerList)
	return providerList
}

// ======================
// Helper Methods
// ======================

// listResourceLevelAssignments lists role assignments for all individual resources in a subscription
func (m *RBACModule) listResourceLevelAssignments(ctx context.Context, subID string,
	authClient *armauthorization.RoleAssignmentsClient, cred *azinternal.StaticTokenCredential, logger internal.Logger) []*armauthorization.RoleAssignment {

	// Get all resources in the subscription
	resourcesClient, err := armresources.NewClient(subID, cred, azinternal.DefaultARMClientOptions())
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create resources client for subscription %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
		return nil
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating individual resource-level RBAC assignments for subscription %s", subID), globals.AZ_RBAC_MODULE_NAME)
	}

	// Collect all resource IDs first, then query in parallel
	var resourceIDs []string
	pager := resourcesClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list resources in subscription %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
			break
		}
		for _, resource := range page.Value {
			if resource.ID != nil {
				resourceIDs = append(resourceIDs, *resource.ID)
			}
		}
	}

	if len(resourceIDs) == 0 {
		return nil
	}

	// Query role assignments in parallel with semaphore
	var mu sync.Mutex
	var wg sync.WaitGroup
	var assignments []*armauthorization.RoleAssignment
	sem := make(chan struct{}, 20) // 20 concurrent resource-level queries

	for _, rid := range resourceIDs {
		wg.Add(1)
		go func(resourceID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var resourceAssignments []*armauthorization.RoleAssignment
			scopePager := authClient.NewListForScopePager(resourceID, nil)
			for scopePager.More() {
				page, err := scopePager.NextPage(ctx)
				if err != nil {
					logger.ErrorM(fmt.Sprintf("Failed to list role assignments for resource %s: %v", resourceID, err), globals.AZ_RBAC_MODULE_NAME)
					break
				}
				resourceAssignments = append(resourceAssignments, page.Value...)
			}
			if len(resourceAssignments) > 0 {
				mu.Lock()
				assignments = append(assignments, resourceAssignments...)
				mu.Unlock()
			}
		}(rid)
	}
	wg.Wait()

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Scanned %d resources, found %d resource-level role assignments", len(resourceIDs), len(assignments)), globals.AZ_RBAC_MODULE_NAME)
	}

	return assignments
}

// resolveNestedGroupChain resolves the nested group membership chain for a given group.
// Returns a formatted string like "ParentGroup1, ParentGroup2, ParentGroup3 (nested)".
// Uses the bulk group memberships cache exclusively (no API fallback) since the pre-fetch
// phase should have populated all group memberships.
func (m *RBACModule) resolveNestedGroupChain(_ context.Context, groupID string, _ internal.Logger) string {
	if groupID == "" {
		return ""
	}

	bulkKey := azinternal.AzCacheKey("group-memberships-all", "tenant")
	if cached, found := azinternal.AzureDataCache.Get(bulkKey); found {
		bulkData := cached.(map[string]azinternal.CachedGroupMembership)
		if membership, ok := bulkData[groupID]; ok && len(membership.AllGroupNames) > 0 {
			return fmt.Sprintf("%s (nested)", strings.Join(membership.AllGroupNames, ", "))
		}
	}
	return ""
}

// ======================
// writeOutput - Stream all collected RBAC data from disk to final output files
// ======================
func (m *RBACModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.rbacRowCount == 0 {
		logger.InfoM("No RBAC assignments found", globals.AZ_RBAC_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Dataset size: %d rows (disk-backed)", m.rbacRowCount), "output")

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
		m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Generate loot files by streaming through the temp file
	lootFiles := m.generateRBACLootFiles()

	// Build output directory path
	resultsIdentifier := internal.BuildResultsIdentifier(scopeType, scopeIDs, scopeNames)
	outDirectoryPath := internal.BuildOutputPath(m.OutputDirectory, "Azure", m.UserUPN, resultsIdentifier)

	if err := os.MkdirAll(outDirectoryPath, 0o755); err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating output directory: %v", err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Stream rows from temp file directly to final output files
	if err := m.streamRBACRowsToOutput(outDirectoryPath, logger); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Write loot files
	for _, l := range lootFiles {
		lootDir := internal.BuildLootDir(outDirectoryPath)
		if err := os.MkdirAll(lootDir, 0o755); err != nil {
			logger.ErrorM(fmt.Sprintf("Error creating loot directory: %v", err), globals.AZ_RBAC_MODULE_NAME)
			continue
		}
		lootPath := internal.BuildLootPath(outDirectoryPath, l.Name)
		if err := os.WriteFile(lootPath, []byte(l.Contents), 0644); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing loot file: %v", err), globals.AZ_RBAC_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("Output written to %s", lootPath), globals.AZ_RBAC_MODULE_NAME)
		}
	}
}

// streamRBACRowsToOutput streams all rows from the temp CSV file to final CSV, JSONL, and table files.
func (m *RBACModule) streamRBACRowsToOutput(outDir string, logger internal.Logger) error {
	safeName := "rbac"

	// CSV
	csvDir := internal.BuildCSVDir(outDir)
	if err := os.MkdirAll(csvDir, 0o755); err != nil {
		return err
	}
	csvPath := internal.BuildCSVPath(outDir, safeName)
	csvFile, err := os.Create(csvPath)
	if err != nil {
		return fmt.Errorf("failed to create csv file: %w", err)
	}
	defer csvFile.Close()
	csvWriter := csv.NewWriter(csvFile)
	_ = csvWriter.Write(RBACHeader)

	// JSONL
	jsonDir := internal.BuildJSONDir(outDir)
	if err := os.MkdirAll(jsonDir, 0o755); err != nil {
		return err
	}
	jsonlPath := internal.BuildJSONLPath(outDir, safeName)
	jsonlFile, err := os.Create(jsonlPath)
	if err != nil {
		return fmt.Errorf("failed to create jsonl file: %w", err)
	}
	defer jsonlFile.Close()

	// Table
	tableDir := internal.BuildTableDir(outDir)
	if err := os.MkdirAll(tableDir, 0o755); err != nil {
		return err
	}
	tablePath := internal.BuildTablePath(outDir, safeName)
	tableFile, err := os.Create(tablePath)
	if err != nil {
		return fmt.Errorf("failed to create table file: %w", err)
	}
	defer tableFile.Close()
	_, _ = tableFile.WriteString(strings.Join(RBACHeader, "\t") + "\n")

	// Stream all rows
	jsonEncoder := json.NewEncoder(jsonlFile)
	err = m.iterateRBACRows(func(row []string) {
		_ = csvWriter.Write(row)

		rowMap := make(map[string]string, len(RBACHeader))
		for i, col := range row {
			if i < len(RBACHeader) {
				rowMap[RBACHeader[i]] = col
			}
		}
		_ = jsonEncoder.Encode(rowMap)

		_, _ = tableFile.WriteString(strings.Join(row, "\t") + "\n")
	})
	csvWriter.Flush()

	logger.InfoM(fmt.Sprintf("Output written to %s", csvPath), globals.AZ_RBAC_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Output written to %s", jsonlPath), globals.AZ_RBAC_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Output written to %s", tablePath), globals.AZ_RBAC_MODULE_NAME)

	return err
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
	_ = m.iterateRBACRows(func(row []string) {
		if len(row) < 16 {
			return
		}
		roleName := row[4]
		principalType := row[3]

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
	})

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

	// Single pass: collect SP data
	type spEntry struct {
		Name, AppID, GUID, Tenant, Role, Scope string
	}
	var spEntries []spEntry
	seenSPs := make(map[string]bool)

	_ = m.iterateRBACRows(func(row []string) {
		if len(row) < 16 {
			return
		}
		principalType := row[3]
		if principalType != "ServicePrincipal" && principalType != "Application" {
			return
		}
		foundSP = true
		principalGUID := row[0]
		if seenSPs[principalGUID] {
			return
		}
		seenSPs[principalGUID] = true
		spEntries = append(spEntries, spEntry{
			Name: row[1], AppID: row[2], GUID: principalGUID,
			Tenant: row[8], Role: row[4], Scope: row[13],
		})
	})

	if !foundSP {
		return ""
	}

	for _, sp := range spEntries {
		loot.WriteString(fmt.Sprintf("## Service Principal: %s\n", sp.Name))
		loot.WriteString(fmt.Sprintf("Application ID: %s\n", sp.AppID))
		loot.WriteString(fmt.Sprintf("Object ID: %s\n", sp.GUID))
		loot.WriteString(fmt.Sprintf("Tenant: %s\n", sp.Tenant))
		loot.WriteString(fmt.Sprintf("Role: %s\n", sp.Role))
		loot.WriteString(fmt.Sprintf("Scope: %s\n", sp.Scope))
		loot.WriteString("\nEnumeration commands:\n")
		loot.WriteString(fmt.Sprintf("# Get service principal details\n"))
		loot.WriteString(fmt.Sprintf("az ad sp show --id %s\n\n", sp.GUID))
		loot.WriteString(fmt.Sprintf("# Check for credentials (secrets/certificates)\n"))
		loot.WriteString(fmt.Sprintf("az ad app credential list --id %s\n\n", sp.AppID))
		loot.WriteString(fmt.Sprintf("# Check for federated credentials (OIDC/GitHub Actions)\n"))
		loot.WriteString(fmt.Sprintf("az ad app federated-credential list --id %s\n\n", sp.AppID))
		loot.WriteString(fmt.Sprintf("# List all roles for this service principal\n"))
		loot.WriteString(fmt.Sprintf("az role assignment list --assignee %s --all\n", sp.GUID))
		loot.WriteString("\n---\n\n")
	}

	return loot.String()
}

// generateRBACCommandsLoot generates commands for further RBAC enumeration
func (m *RBACModule) generateRBACCommandsLoot() string {
	var loot strings.Builder

	loot.WriteString("# RBAC Enumeration Commands\n")
	loot.WriteString("# Use these commands to enumerate RBAC permissions and identify privilege escalation opportunities\n\n")

	// Collect unique tenants and subscriptions (streaming from disk)
	tenantsMap := make(map[string]string)
	subscriptionsMap := make(map[string]bool)

	_ = m.iterateRBACRows(func(row []string) {
		if len(row) < 16 {
			return
		}
		tenantID := row[9]
		tenantName := row[8]
		subscriptionScope := row[11]

		if tenantID != "N/A" {
			tenantsMap[tenantID] = tenantName
		}
		if subscriptionScope != "N/A" {
			subscriptionsMap[subscriptionScope] = true
		}
	})

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

	// Track which escalation paths are relevant based on roles found (streaming from disk)
	foundRoles := make(map[string]bool)
	_ = m.iterateRBACRows(func(row []string) {
		if len(row) > 4 {
			foundRoles[row[4]] = true
		}
	})

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
