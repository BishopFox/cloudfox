package commands

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

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
	Subscriptions    []string
	LootMap          map[string]*internal.LootFile
	collectedMIs     []azinternal.ManagedIdentity     // For callback access during MI enumeration
	enrichmentWriter *azinternal.EnrichmentCacheWriter // Per-principal JSONL cache writer
	mu               sync.Mutex

	// Disk-backed row storage (avoids OOM on large tenants)
	principalRowFile  *os.File
	principalRowCount int
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

// openPrincipalRowFile creates a temp CSV file for streaming principal rows to disk.
func (m *PrincipalsModule) openPrincipalRowFile() error {
	f, err := os.CreateTemp("", "cloudfox-principals-*.csv")
	if err != nil {
		return fmt.Errorf("failed to create temp row file: %w", err)
	}
	m.principalRowFile = f
	m.principalRowCount = 0
	return nil
}

// writePrincipalRow writes a single row to the temp CSV file.
func (m *PrincipalsModule) writePrincipalRow(row []string) {
	if m.principalRowFile == nil {
		return
	}
	w := csv.NewWriter(m.principalRowFile)
	_ = w.Write(row)
	w.Flush()
	m.principalRowCount++
}

// closePrincipalRowFile closes the temp CSV file.
func (m *PrincipalsModule) closePrincipalRowFile() {
	if m.principalRowFile != nil {
		m.principalRowFile.Close()
	}
}

// removePrincipalRowFile deletes the temp CSV file.
func (m *PrincipalsModule) removePrincipalRowFile() {
	if m.principalRowFile != nil {
		os.Remove(m.principalRowFile.Name())
	}
}

// iteratePrincipalRows streams through all rows in the temp file, calling fn for each row.
func (m *PrincipalsModule) iteratePrincipalRows(fn func(row []string)) error {
	if m.principalRowFile == nil {
		return nil
	}
	if _, err := m.principalRowFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek temp row file: %w", err)
	}
	r := csv.NewReader(bufio.NewReaderSize(m.principalRowFile, 256*1024))
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		fn(row)
	}
	return nil
}

// loadPrincipalEnrichmentCacheToDisk streams the enrichment cache JSONL file directly to the
// temp CSV file on disk, returning only the skip set in memory.
func (m *PrincipalsModule) loadPrincipalEnrichmentCacheToDisk(baseDir, tenantID string) (skipSet map[string]bool, count int, loot string, err error) {
	cachePath := azinternal.EnrichmentCacheFilePath(baseDir, tenantID)
	file, err := os.Open(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, "", nil
		}
		return nil, 0, "", err
	}
	defer file.Close()

	skipSet = make(map[string]bool)
	w := csv.NewWriter(m.principalRowFile)
	var lootBuilder strings.Builder

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry azinternal.EnrichmentCacheEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.PrincipalID == "" {
			continue
		}
		if skipSet[entry.PrincipalID] {
			continue // dedup: skip earlier entries
		}
		skipSet[entry.PrincipalID] = true
		if len(entry.Row) > 0 {
			_ = w.Write(entry.Row)
			m.principalRowCount++
		}
		lootBuilder.WriteString(entry.Loot)
	}
	w.Flush()
	count = len(skipSet)

	if count == 0 {
		return nil, 0, "", nil
	}
	return skipSet, count, lootBuilder.String(), nil
}

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListPrincipals(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_PRINCIPALS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}

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
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 30),
		Subscriptions:   cmdCtx.Subscriptions,
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
	// Open temp file for streaming rows to disk
	if err := m.openPrincipalRowFile(); err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to open temp row file: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		return
	}
	defer m.removePrincipalRowFile()
	defer m.closePrincipalRowFile()

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
	internal.PrintPhaseStatus(globals.AZ_PRINCIPALS_MODULE_NAME, "Enumerating users...")
	users, uErr := azinternal.ListEntraUsers(ctx, m.Session, m.TenantID)
	if uErr == nil {
		internal.PrintPhaseDone(globals.AZ_PRINCIPALS_MODULE_NAME, fmt.Sprintf("Enumerating users: found %d", len(users)))
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
		internal.PrintPhaseDone(globals.AZ_PRINCIPALS_MODULE_NAME, "Enumerating users: failed")
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list Entra users: %v", uErr), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// 2) Service Principals
	internal.PrintPhaseStatus(globals.AZ_PRINCIPALS_MODULE_NAME, "Enumerating service principals...")
	sps, spErr := azinternal.ListServicePrincipals(ctx, m.Session, m.TenantID)
	if spErr == nil {
		internal.PrintPhaseDone(globals.AZ_PRINCIPALS_MODULE_NAME, fmt.Sprintf("Enumerating service principals: found %d", len(sps)))
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
		internal.PrintPhaseDone(globals.AZ_PRINCIPALS_MODULE_NAME, "Enumerating service principals: failed")
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list service principals: %v", spErr), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// 3) Security Groups
	internal.PrintPhaseStatus(globals.AZ_PRINCIPALS_MODULE_NAME, "Enumerating groups...")
	groups, grpErr := azinternal.ListEntraGroups(ctx, m.Session, m.TenantID)
	if grpErr == nil {
		internal.PrintPhaseDone(globals.AZ_PRINCIPALS_MODULE_NAME, fmt.Sprintf("Enumerating groups: found %d", len(groups)))
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
		internal.PrintPhaseDone(globals.AZ_PRINCIPALS_MODULE_NAME, "Enumerating groups: failed")
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list security groups: %v", grpErr), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// 4) User-assigned Managed Identities
	internal.PrintPhaseStatus(globals.AZ_PRINCIPALS_MODULE_NAME, "Enumerating managed identities...")

	// Initialize MI collection list
	m.collectedMIs = []azinternal.ManagedIdentity{}

	// Reset CommandCounter before MI subscription enumeration
	m.CommandCounter = internal.CommandCounter{}

	// Use RunSubscriptionEnumeration for standardized processing
	m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_PRINCIPALS_MODULE_NAME, m.processSubscriptionForMIs)

	// Add collected MIs to principals list
	for _, mi := range m.collectedMIs {
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

	// --- Enrichment cache: load previously enriched principals for resume ---
	// Note: --refresh-cache deletes the enrichment file in PersistentPreRun,
	// so this naturally finds nothing when refreshing.
	var skipSet map[string]bool
	totalPrincipals := len(principals)

	if azinternal.EnrichmentCacheExists(m.OutputDirectory, m.TenantID) {
		if azinternal.IsEnrichmentCacheStale(m.OutputDirectory, m.TenantID, azinternal.DefaultAzureCacheExpiration) {
			age, _ := azinternal.GetEnrichmentCacheAge(m.OutputDirectory, m.TenantID)
			logger.InfoM(fmt.Sprintf("Enrichment cache is stale (age: %s). Use --refresh-cache to force update.", azinternal.FormatCacheAge(age)), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		// Stream cached rows directly to disk temp file (avoids loading into memory)
		ss, count, loot, err := m.loadPrincipalEnrichmentCacheToDisk(m.OutputDirectory, m.TenantID)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to load enrichment cache, re-enriching all: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		} else if ss != nil {
			skipSet = ss
			m.LootMap["principal-commands"].Contents += loot
			logger.InfoM(fmt.Sprintf("Resuming: loaded %d cached enrichments", count), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// Open enrichment cache writer
	writer, err := azinternal.NewEnrichmentCacheWriter(m.OutputDirectory, m.TenantID)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to open enrichment cache writer: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
	} else {
		m.enrichmentWriter = writer
		defer func() {
			m.enrichmentWriter.Close()
			m.enrichmentWriter = nil
		}()
	}

	// Process principals with centralized progress tracking, skipping cached ones
	m.CommandCounter = internal.CommandCounter{}
	principalMap := make(map[string]Principal, len(principals))
	var principalIDs []string
	for _, p := range principals {
		principalMap[p.PrincipalID] = p
		if skipSet != nil && skipSet[p.PrincipalID] {
			continue
		}
		principalIDs = append(principalIDs, p.PrincipalID)
	}

	if len(skipSet) > 0 {
		logger.InfoM(fmt.Sprintf("Enriching %d principals (%d already cached, %d total)", len(principalIDs), len(skipSet), totalPrincipals), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	if len(principalIDs) == 0 {
		logger.InfoM("All principals already cached, skipping enrichment", globals.AZ_PRINCIPALS_MODULE_NAME)
		return
	}

	// ========================================================================
	// PHASE 1: DOWNLOAD (all API calls)
	// ========================================================================
	spinner := internal.NewPhaseSpinner(globals.AZ_PRINCIPALS_MODULE_NAME)

	var preFetchWg sync.WaitGroup

	// Collect user IDs for MFA bulk pre-fetch
	var userIDs []string
	for _, p := range principals {
		if p.Type == "User" || p.Type == "Guest" {
			userIDs = append(userIDs, p.PrincipalID)
		}
	}

	// Tenant-level bulk pre-fetches
	spinner.Add("CA policies")
	preFetchWg.Add(1)
	go func() {
		defer preFetchWg.Done()
		defer spinner.Done("CA policies")
		if err := azinternal.PreFetchConditionalAccessPolicies(ctx, m.Session, m.OutputDirectory, m.TenantID); err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("CA policy pre-fetch failed (will fall back to per-principal): %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
		}
	}()

	spinner.Add("PIM directory roles")
	preFetchWg.Add(1)
	go func() {
		defer preFetchWg.Done()
		defer spinner.Done("PIM directory roles")
		azinternal.PreFetchPIMDirectoryRoles(ctx, m.Session, m.OutputDirectory, m.TenantID)
	}()

	spinner.Add("group memberships")
	preFetchWg.Add(1)
	go func() {
		defer preFetchWg.Done()
		defer spinner.Done("group memberships")
		azinternal.PreFetchGroupMemberships(ctx, m.Session, m.OutputDirectory, m.TenantID)
	}()

	spinner.Add("directory roles")
	preFetchWg.Add(1)
	go func() {
		defer preFetchWg.Done()
		defer spinner.Done("directory roles")
		azinternal.PreFetchDirectoryRoleMembers(ctx, m.Session, m.OutputDirectory, m.TenantID)
	}()

	spinner.Add("sign-in activity")
	preFetchWg.Add(1)
	go func() {
		defer preFetchWg.Done()
		defer spinner.Done("sign-in activity")
		azinternal.PreFetchSignInActivity(ctx, m.Session, m.OutputDirectory, m.TenantID)
	}()

	spinner.Add("OAuth2 grants")
	preFetchWg.Add(1)
	go func() {
		defer preFetchWg.Done()
		defer spinner.Done("OAuth2 grants")
		azinternal.PreFetchOAuth2Grants(ctx, m.Session, m.OutputDirectory, m.TenantID)
	}()

	spinner.Add("SP permissions")
	preFetchWg.Add(1)
	go func() {
		defer preFetchWg.Done()
		defer spinner.Done("SP permissions")
		azinternal.PreFetchSPAppRoleAssignments(ctx, m.Session, m.OutputDirectory, m.TenantID)
	}()

	// MFA: bulk pre-fetch via Graph $batch API (unless --skip-mfa)
	if !globals.AZ_SKIP_MFA && len(userIDs) > 0 {
		spinner.Add("MFA methods")
		preFetchWg.Add(1)
		go func() {
			defer preFetchWg.Done()
			defer spinner.Done("MFA methods")
			azinternal.PreFetchMFABulk(ctx, m.Session, m.OutputDirectory, m.TenantID, userIDs)
		}()
	}

	// PIM + RBAC: per-subscription with concurrency limit to avoid thundering herd
	subSem := make(chan struct{}, 5)
	for _, sub := range m.Subscriptions {
		spinner.Add("PIM roles")
		spinner.Add("RBAC assignments")
		preFetchWg.Add(1)
		go func(subID string) {
			defer preFetchWg.Done()
			subSem <- struct{}{}
			defer func() { <-subSem }()
			azinternal.PreFetchPIMRolesForSubscription(ctx, m.Session, subID, m.OutputDirectory, m.TenantID)
			spinner.Done("PIM roles")
			azinternal.PreFetchRBACAssignmentsForSubscription(ctx, m.Session, subID, m.OutputDirectory, m.TenantID)
			spinner.Done("RBAC assignments")
		}(sub)
	}

	preFetchWg.Wait()
	spinner.Stop("Pre-fetching tenant data: done")

	// ========================================================================
	// PHASE 2: ENRICH (zero API calls, pure computation from bulk caches)
	// ========================================================================
	internal.PrintPhaseStatus(globals.AZ_PRINCIPALS_MODULE_NAME, fmt.Sprintf("Building rows for %d principals...", len(principalIDs)))

	m.buildAllRows(ctx, logger, principalIDs, principalMap, contextLabel, subNameMap)

	internal.PrintPhaseDone(globals.AZ_PRINCIPALS_MODULE_NAME, fmt.Sprintf("Built %d principal rows", m.principalRowCount))
}

// processSubscriptionForMIs processes a single subscription for managed identity collection
func (m *PrincipalsModule) processSubscriptionForMIs(ctx context.Context, subID string, logger internal.Logger) {
	mis, miErr := azinternal.ListUserAssignedManagedIdentities(ctx, m.Session, []string{subID})
	if miErr == nil {
		m.mu.Lock()
		m.collectedMIs = append(m.collectedMIs, mis...)
		m.mu.Unlock()
	} else {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list managed identities in subscription %s: %v", subID, miErr), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}
}

// buildAllRows performs Phase 2 enrichment: pure computation from bulk caches,
// zero API calls. Replaces the per-principal goroutine fan-out with a single
// sequential pass over all principals using pre-computed indexes.
func (m *PrincipalsModule) buildAllRows(_ context.Context, logger internal.Logger, principalIDs []string, principalMap map[string]Principal, contextLabel string, subNameMap map[string]string) {
	// Load all bulk caches from in-memory AzureDataCache (populated by Phase 1 pre-fetch)
	groupCacheKey := azinternal.AzCacheKey("group-memberships-all", "tenant")
	dirRoleCacheKey := azinternal.AzCacheKey("directory-role-members-all", "tenant")
	pimDirEligibleKey := azinternal.AzCacheKey("pim-dir-eligible-all", "tenant")
	pimDirActiveKey := azinternal.AzCacheKey("pim-dir-active-all", "tenant")
	signInCacheKey := azinternal.AzCacheKey("sign-in-activity-all", "tenant")
	oauth2CacheKey := azinternal.AzCacheKey("oauth2-grants-all", "tenant")
	spAppRoleCacheKey := azinternal.AzCacheKey("sp-approle-assignments-all", "tenant")
	mfaCacheKey := azinternal.AzCacheKey("mfa-all", "tenant")

	// Type-assert each cache (nil-safe: if cache not populated, use empty maps)
	var groupCache map[string]azinternal.CachedGroupMembership
	if cached, found := azinternal.AzureDataCache.Get(groupCacheKey); found {
		groupCache = cached.(map[string]azinternal.CachedGroupMembership)
	}

	var dirRoleCache map[string][]azinternal.DirectoryRole
	if cached, found := azinternal.AzureDataCache.Get(dirRoleCacheKey); found {
		dirRoleCache = cached.(map[string][]azinternal.DirectoryRole)
	}

	var pimDirEligible map[string][]azinternal.DirectoryRole
	if cached, found := azinternal.AzureDataCache.Get(pimDirEligibleKey); found {
		pimDirEligible = cached.(map[string][]azinternal.DirectoryRole)
	}

	var pimDirActive map[string][]azinternal.DirectoryRole
	if cached, found := azinternal.AzureDataCache.Get(pimDirActiveKey); found {
		pimDirActive = cached.(map[string][]azinternal.DirectoryRole)
	}

	var signInCache map[string]azinternal.SignInActivity
	if cached, found := azinternal.AzureDataCache.Get(signInCacheKey); found {
		signInCache = cached.(map[string]azinternal.SignInActivity)
	}

	var oauth2Cache map[string][]azinternal.CachedOAuth2Grant
	if cached, found := azinternal.AzureDataCache.Get(oauth2CacheKey); found {
		oauth2Cache = cached.(map[string][]azinternal.CachedOAuth2Grant)
	}

	var spAppRoleCache map[string][]azinternal.CachedSPAppRoleAssignment
	if cached, found := azinternal.AzureDataCache.Get(spAppRoleCacheKey); found {
		spAppRoleCache = cached.(map[string][]azinternal.CachedSPAppRoleAssignment)
	}

	var mfaCache map[string]azinternal.MFAAuthenticationMethods
	if cached, found := azinternal.AzureDataCache.Get(mfaCacheKey); found {
		mfaCache = cached.(map[string]azinternal.MFAAuthenticationMethods)
	}

	// Pre-compute per-subscription RBAC + PIM indexes using bulk caches only (zero API calls).
	// This replaces per-principal GetEnhancedRBACAssignments calls which could trigger
	// GetUserGroupMemberships API fallbacks for principals not in the bulk group cache.
	rbacIndex, inheritedIndex, pimSubEligibleIndex, pimSubActiveIndex := azinternal.BuildRBACIndexFromCaches(
		m.Subscriptions, subNameMap, groupCache, principalIDs,
	)

	// Pre-compute CA policy index (zero API calls, pure cache iteration)
	caIndex := azinternal.BuildCAPolicyIndex(groupCache, principalIDs)

	// Batch buffer for enrichment cache writes
	var rowBatch []azinternal.EnrichmentCacheEntry

	// Single-pass row building: iterate all principals sequentially
	for _, pid := range principalIDs {
		p := principalMap[pid]

		// Normalize fields
		upn := p.UPN
		if upn == "" {
			upn = "N/A"
		}
		dname := p.DisplayName
		if dname == "" {
			dname = "N/A"
		}
		objID := p.PrincipalID
		if objID == "" {
			objID = "N/A"
		}

		// Group memberships: pure map lookup
		groupMemberships := ""
		if groupCache != nil {
			if gm, ok := groupCache[p.PrincipalID]; ok {
				groupMemberships = azinternal.FormatNestedGroupMemberships(gm.DirectGroupNames, gm.AllGroupNames)
			}
		}

		// Directory roles: pure map lookup
		directoryRolesStr := ""
		if dirRoleCache != nil {
			if roles, ok := dirRoleCache[p.PrincipalID]; ok {
				directoryRolesStr = azinternal.FormatDirectoryRoles(roles)
			}
		}

		// MFA: from bulk cache or skip
		mfaEnabled := "N/A"
		mfaMethods := "N/A"
		mfaDefaultMethod := "N/A"
		if globals.AZ_SKIP_MFA {
			mfaEnabled = "N/A (skipped)"
			mfaMethods = "N/A (skipped)"
			mfaDefaultMethod = "N/A (skipped)"
		} else if (p.Type == "User" || p.Type == "Guest") && mfaCache != nil {
			if mfa, ok := mfaCache[p.PrincipalID]; ok {
				if mfa.MFAEnabled {
					mfaEnabled = "Yes"
					mfaMethods = strings.Join(mfa.Methods, ", ")
					if mfa.DefaultMethod != "" {
						mfaDefaultMethod = mfa.DefaultMethod
					}
				} else {
					mfaEnabled = "No"
					mfaMethods = "None"
					mfaDefaultMethod = "None"
				}
			}
		}

		// Sign-in activity: pure map lookup
		lastSignIn := "N/A"
		lastNonInteractiveSignIn := "N/A"
		daysSinceSignIn := "N/A"
		staleAccount := "No"
		if (p.Type == "User" || p.Type == "Guest") && signInCache != nil {
			if si, ok := signInCache[p.PrincipalID]; ok {
				m.applySignInData(si, &lastSignIn, &lastNonInteractiveSignIn, &daysSinceSignIn, &staleAccount)
			}
		}

		// Graph permissions: pure map lookup from SP appRole cache
		graphPerms := ""
		if p.Type == "ServicePrincipal" && spAppRoleCache != nil {
			if assignments, ok := spAppRoleCache[p.PrincipalID]; ok {
				var perms []string
				for _, a := range assignments {
					perms = append(perms, fmt.Sprintf("%s: %s", a.ResourceDisplayName, a.AppRoleName))
				}
				graphPerms = strings.Join(perms, "\n")
			}
		}

		// Delegated OAuth2 grants: pure map lookup
		delegatedStr := ""
		if oauth2Cache != nil {
			if grants, ok := oauth2Cache[p.PrincipalID]; ok {
				var parts []string
				for _, g := range grants {
					for _, scope := range g.Scopes {
						parts = append(parts, fmt.Sprintf("%s: %s (%s)", g.ResourceName, scope, g.ConsentType))
					}
				}
				delegatedStr = strings.Join(parts, ", ")
			}
		}

		// RBAC: from pre-computed index
		rbacStr := ""
		if roles, ok := rbacIndex[p.PrincipalID]; ok && len(roles) > 0 {
			rbacStr = strings.Join(roles, "\n")
		}

		// Inherited permissions: from pre-computed index
		inheritedStr := ""
		if inh, ok := inheritedIndex[p.PrincipalID]; ok && len(inh) > 0 {
			inheritedStr = strings.Join(inh, "\n")
		}

		// PIM: directory roles + subscription roles
		pimStr := ""

		// Subscription PIM
		if eligible, ok := pimSubEligibleIndex[p.PrincipalID]; ok && len(eligible) > 0 {
			pimStr = "Eligible: " + strings.Join(eligible, ", ")
		}
		if active, ok := pimSubActiveIndex[p.PrincipalID]; ok && len(active) > 0 {
			if pimStr != "" {
				pimStr += "\n"
			}
			pimStr += "Active: " + strings.Join(active, ", ")
		}

		// Directory PIM (tenant-scoped)
		if pimDirEligible != nil {
			if roles, ok := pimDirEligible[p.PrincipalID]; ok && len(roles) > 0 {
				if pimStr != "" {
					pimStr += "\n"
				}
				var eligibleDirRoles []string
				for _, role := range roles {
					eligibleDirRoles = append(eligibleDirRoles, fmt.Sprintf("%s (Entra ID)", role.DisplayName))
				}
				pimStr += "Eligible Directory: " + strings.Join(eligibleDirRoles, ", ")
			}
		}
		if pimDirActive != nil {
			if roles, ok := pimDirActive[p.PrincipalID]; ok && len(roles) > 0 {
				if pimStr != "" {
					pimStr += "\n"
				}
				var activeDirRoles []string
				for _, role := range roles {
					activeDirRoles = append(activeDirRoles, fmt.Sprintf("%s (Entra ID)", role.DisplayName))
				}
				pimStr += "Active Directory: " + strings.Join(activeDirRoles, ", ")
			}
		}

		// Conditional Access: from pre-computed index (zero API calls)
		caStr := caIndex[p.PrincipalID]

		// Build row
		row := []string{
			m.TenantName,
			m.TenantID,
			contextLabel,
			p.Service,
			p.Type,
			upn,
			dname,
			objID,
			mfaEnabled,
			mfaMethods,
			mfaDefaultMethod,
			lastSignIn,
			lastNonInteractiveSignIn,
			daysSinceSignIn,
			staleAccount,
			groupMemberships,
			rbacStr,
			directoryRolesStr,
			pimStr,
			inheritedStr,
			caStr,
			graphPerms,
			delegatedStr,
		}
		loot := m.generateLootForPrincipal(p)

		m.writePrincipalRow(row)
		m.LootMap["principal-commands"].Contents += loot

		// Buffer enrichment cache writes (batch of 1000)
		if m.enrichmentWriter != nil {
			rowBatch = append(rowBatch, azinternal.EnrichmentCacheEntry{
				PrincipalID: p.PrincipalID,
				Row:         row,
				Loot:        loot,
				Timestamp:   time.Now().Unix(),
			})
			if len(rowBatch) >= 1000 {
				for _, entry := range rowBatch {
					m.enrichmentWriter.Append(entry)
				}
				rowBatch = rowBatch[:0]
			}
		}
	}

	// Flush remaining buffered enrichment cache entries
	if m.enrichmentWriter != nil && len(rowBatch) > 0 {
		for _, entry := range rowBatch {
			m.enrichmentWriter.Append(entry)
		}
	}
}

// applySignInData formats sign-in activity fields from a SignInActivity struct.
func (m *PrincipalsModule) applySignInData(si azinternal.SignInActivity, lastSignIn, lastNonInteractive, daysSince, stale *string) {
	if si.LastSignInDateTime != "Never" {
		if t, err := time.Parse(time.RFC3339, si.LastSignInDateTime); err == nil {
			*lastSignIn = t.Format("2006-01-02 15:04")
		} else {
			*lastSignIn = si.LastSignInDateTime
		}
	} else {
		*lastSignIn = "Never"
	}

	if si.LastNonInteractiveSignInDateTime != "Never" {
		if t, err := time.Parse(time.RFC3339, si.LastNonInteractiveSignInDateTime); err == nil {
			*lastNonInteractive = t.Format("2006-01-02 15:04")
		} else {
			*lastNonInteractive = si.LastNonInteractiveSignInDateTime
		}
	} else {
		*lastNonInteractive = "Never"
	}

	if si.DaysSinceLastSignIn >= 0 {
		*daysSince = fmt.Sprintf("%d days", si.DaysSinceLastSignIn)
	} else {
		*daysSince = "Never"
	}

	if si.IsStale {
		*stale = fmt.Sprintf("⚠ Yes (%s)", si.StaleReason)
	}
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
	if m.principalRowCount == 0 {
		logger.InfoM("No Principals found", globals.AZ_PRINCIPALS_MODULE_NAME)
		return
	}

	// Build headers with new columns
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Tenant/Subscription Context",
		"Source Service",
		"Principal Type",
		"User Principal Name / App ID",
		"Display Name",
		"Object ID",
		"MFA Enabled",
		"MFA Methods",
		"Default MFA Method",
		"Last Sign-In (Interactive)",
		"Last Sign-In (Non-Interactive)",
		"Days Since Last Sign-In",
		"Stale Account (>90 days)",
		"Group Memberships (incl. Nested)",
		"RBAC Roles (with Scope Hierarchy)",
		"Entra ID Directory Roles",
		"PIM Status (Eligible/Active)",
		"Inherited Permissions",
		"Conditional Access Policies",
		"Graph API Permissions",
		"Delegated OAuth2 Grants",
	}

	// Determine output scope
	scopeType := "tenant"
	scopeIDs := []string{m.TenantID}
	var scopeNames []string

	// Build loot array
	var loot []internal.LootFile
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Build output directory path
	resultsIdentifier := internal.BuildResultsIdentifier(scopeType, scopeIDs, scopeNames)
	outDirectoryPath := internal.BuildOutputPath(m.OutputDirectory, "Azure", m.UserUPN, resultsIdentifier)

	if err := os.MkdirAll(outDirectoryPath, 0o755); err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating output directory: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Stream rows from temp file directly to final output files
	if err := m.streamPrincipalRowsToOutput(outDirectoryPath, headers, logger); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Write loot files
	for _, l := range loot {
		lootDir := internal.BuildLootDir(outDirectoryPath)
		if err := os.MkdirAll(lootDir, 0o755); err != nil {
			logger.ErrorM(fmt.Sprintf("Error creating loot directory: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
			continue
		}
		lootPath := internal.BuildLootPath(outDirectoryPath, l.Name)
		if err := os.WriteFile(lootPath, []byte(l.Contents), 0644); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing loot file: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("Output written to %s", lootPath), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d Principal(s) for tenant: %s", m.principalRowCount, m.TenantName), globals.AZ_PRINCIPALS_MODULE_NAME)
}

// streamPrincipalRowsToOutput streams all rows from the temp CSV file to final output files.
func (m *PrincipalsModule) streamPrincipalRowsToOutput(outDir string, headers []string, logger internal.Logger) error {
	safeName := "principals"

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
	_ = csvWriter.Write(headers)

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
	_, _ = tableFile.WriteString(strings.Join(headers, "\t") + "\n")

	jsonEncoder := json.NewEncoder(jsonlFile)
	err = m.iteratePrincipalRows(func(row []string) {
		_ = csvWriter.Write(row)

		rowMap := make(map[string]string, len(headers))
		for i, col := range row {
			if i < len(headers) {
				rowMap[headers[i]] = col
			}
		}
		_ = jsonEncoder.Encode(rowMap)

		_, _ = tableFile.WriteString(strings.Join(row, "\t") + "\n")
	})
	csvWriter.Flush()

	logger.InfoM(fmt.Sprintf("Output written to %s", csvPath), globals.AZ_PRINCIPALS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Output written to %s", jsonlPath), globals.AZ_PRINCIPALS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Output written to %s", tablePath), globals.AZ_PRINCIPALS_MODULE_NAME)

	return err
}
