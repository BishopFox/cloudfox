package azure

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/cacheutil"
	"github.com/patrickmn/go-cache"
)

// AzureDataCache is the centralized in-memory cache for Azure API responses.
// It persists across all commands within a single process (e.g., all-checks).
// Default expiration: 2 hours, cleanup interval: 10 minutes.
var AzureDataCache = cache.New(2*time.Hour, 10*time.Minute)

// AzCacheKey generates a consistent cache key from components.
// Example: AzCacheKey("resource-groups", "sub-123") -> "az-resource-groups-sub-123"
func AzCacheKey(parts ...string) string {
	return "az-" + strings.Join(parts, "-")
}

// ClearAzureCache flushes all entries from the in-memory cache.
func ClearAzureCache() {
	AzureDataCache.Flush()
}

// GetAzureCacheStats returns the number of items currently in the cache.
func GetAzureCacheStats() int {
	return AzureDataCache.ItemCount()
}

// ---------------------------------------------------------------------------
// Bulk cache backfill support
// ---------------------------------------------------------------------------

// bulkCacheMu protects concurrent backfill writes to bulk cache maps.
// The bulk maps are written once during prefetch and read during enrichment.
// Backfill writes happen when a per-principal API fallback succeeds and we
// want to update the bulk map so other goroutines benefit.
var bulkCacheMu sync.Mutex

// bulkCacheBaseDir and bulkCacheTenantID store the disk cache context so that
// backfill helpers can persist updates to disk without requiring callers to
// pass baseDir/tenantID through every getter function.
var (
	bulkCacheBaseDir  string
	bulkCacheTenantID string
)

// SetBulkCacheContext stores the baseDir and tenantID used for disk cache
// persistence. Called by prefetch functions and module initialization.
func SetBulkCacheContext(baseDir, tenantID string) {
	bulkCacheMu.Lock()
	defer bulkCacheMu.Unlock()
	bulkCacheBaseDir = baseDir
	bulkCacheTenantID = tenantID
}

// BackfillBulkCache safely updates a single entry in a bulk cache map (both
// in-memory and on disk). It re-fetches the map from go-cache under the lock
// to avoid races from concurrent enrichment goroutines.
//
// V is the per-entry value type (e.g., CachedGroupMembership, []DirectoryRole).
func BackfillBulkCache[V any](cacheKey, entryKey string, value V) {
	bulkCacheMu.Lock()
	defer bulkCacheMu.Unlock()

	cached, found := AzureDataCache.Get(cacheKey)
	if !found {
		return
	}
	m := cached.(map[string]V)
	m[entryKey] = value
	AzureDataCache.Set(cacheKey, m, cache.DefaultExpiration)

	// Persist to disk if context is available
	if bulkCacheBaseDir != "" && bulkCacheTenantID != "" {
		saveBulkCacheToDisk(cacheKey, m)
	}
}

// EnsureBulkCacheLoaded loads bulk caches from disk into memory if not already present.
// Called by modules that consume caches without calling PreFetch (e.g., when run individually).
// Sets the bulk cache context so that subsequent BackfillBulkCache calls can persist to disk.
func EnsureBulkCacheLoaded(baseDir, tenantID string, cacheKeys ...string) {
	SetBulkCacheContext(baseDir, tenantID)
	for _, key := range cacheKeys {
		if _, found := AzureDataCache.Get(key); found {
			continue // Already in memory
		}
		loadBulkCacheFromDisk(baseDir, tenantID, key)
	}
	ValidateBulkCacheCompleteness(tenantID)
}

// loadBulkCacheFromDisk loads a single bulk cache from its GOB file on disk
// and sets it in the in-memory AzureDataCache. Handles each cache type's
// specific struct and extraction logic.
func loadBulkCacheFromDisk(baseDir, tenantID, cacheKey string) {
	filename, ok := bulkCacheGobFilenames[cacheKey]
	if !ok {
		return
	}

	switch filename {
	case "group-memberships.gob":
		var dc GroupMembershipsCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) {
			AzureDataCache.Set(cacheKey, dc.Data, 0)
			// Rebuild group name map for GetGroupDisplayName lookups
			nameMap := make(map[string]string)
			for _, membership := range dc.Data {
				for i, gid := range membership.AllGroupIDs {
					if i < len(membership.AllGroupNames) {
						nameMap[gid] = membership.AllGroupNames[i]
					}
				}
			}
			AzureDataCache.Set(AzCacheKey("group-names-all", "tenant"), nameMap, 0)
		}
	case "directory-role-members.gob":
		var dc DirectoryRoleMembersCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) {
			AzureDataCache.Set(cacheKey, dc.Data, 0)
		}
	case "oauth2-grants.gob":
		var dc OAuth2GrantsCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) {
			AzureDataCache.Set(cacheKey, dc.Data, 0)
		}
	case "sp-approle-assignments.gob":
		var dc SPAppRoleAssignmentsCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) {
			AzureDataCache.Set(cacheKey, dc.Data, 0)
		}
	case "sign-in-activity.gob":
		var dc SignInActivityCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) {
			AzureDataCache.Set(cacheKey, dc.Data, 0)
		}
	case "ca-policies-full.gob":
		var dc CAPoliciesFullCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) {
			AzureDataCache.Set(cacheKey, dc.Policies, 0)
		}
		// Also load minimal CA cache if available
		var minimalDC CAPoliciesCache
		minimalKey := AzCacheKey("ca-policies-all", "tenant")
		if loadPrefetchCache(baseDir, tenantID, "ca-policies.gob", DefaultAzureCacheExpiration, &minimalDC) {
			AzureDataCache.Set(minimalKey, minimalDC.Policies, 0)
		}
	case "pim-directory.gob":
		var dc PIMDirectoryCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) {
			// PIM directory GOB contains both eligible and active maps
			eligibleKey := AzCacheKey("pim-dir-eligible-all", "tenant")
			activeKey := AzCacheKey("pim-dir-active-all", "tenant")
			if dc.Eligible != nil {
				AzureDataCache.Set(eligibleKey, dc.Eligible, 0)
			}
			if dc.Active != nil {
				AzureDataCache.Set(activeKey, dc.Active, 0)
			}
		}
	case "mfa-bulk.gob":
		var dc MFABulkCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) {
			AzureDataCache.Set(cacheKey, dc.Data, 0)
		}
	}
}

// bulkCacheGobFilenames maps in-memory cache keys to their GOB filenames.
var bulkCacheGobFilenames = map[string]string{
	"az-group-memberships-all-tenant":      "group-memberships.gob",
	"az-directory-role-members-all-tenant":  "directory-role-members.gob",
	"az-oauth2-grants-all-tenant":          "oauth2-grants.gob",
	"az-sp-approle-assignments-all-tenant":  "sp-approle-assignments.gob",
	"az-sign-in-activity-all-tenant":        "sign-in-activity.gob",
	"az-ca-policies-full-tenant":            "ca-policies-full.gob",
	"az-pim-dir-eligible-all-tenant":        "pim-directory.gob",
	"az-pim-dir-active-all-tenant":          "pim-directory.gob",
	"az-mfa-all-tenant":                     "mfa-bulk.gob",
}

// saveBulkCacheToDisk persists the bulk cache map to disk using the appropriate
// GOB wrapper struct. Uses a cross-process file lock to prevent concurrent
// CloudFox processes from clobbering each other's backfill entries. The lock
// covers a load-merge-write cycle: we read the existing GOB, merge in-memory
// entries on top, and write the result atomically.
//
// Caller must hold bulkCacheMu (in-process lock).
func saveBulkCacheToDisk(cacheKey string, data any) {
	filename, ok := bulkCacheGobFilenames[cacheKey]
	if !ok {
		return
	}

	cacheDir := GetAzureCacheDirectory(bulkCacheBaseDir, bulkCacheTenantID)
	gobPath := filepath.Join(cacheDir, filename)

	// Acquire cross-process file lock
	flock, err := cacheutil.AcquireFileLock(gobPath)
	if err != nil {
		return // Best-effort; in-memory cache is still correct
	}
	defer flock.Release()

	// Load existing disk data and merge our in-memory map on top.
	// This preserves entries written by other processes.
	var wrapped any
	switch filename {
	case "group-memberships.gob":
		merged := mergeDiskMap[CachedGroupMembership](bulkCacheBaseDir, bulkCacheTenantID, filename, data.(map[string]CachedGroupMembership))
		wrapped = GroupMembershipsCache{Data: merged}
	case "directory-role-members.gob":
		merged := mergeDiskMap[[]DirectoryRole](bulkCacheBaseDir, bulkCacheTenantID, filename, data.(map[string][]DirectoryRole))
		wrapped = DirectoryRoleMembersCache{Data: merged}
	case "oauth2-grants.gob":
		merged := mergeDiskMap[[]CachedOAuth2Grant](bulkCacheBaseDir, bulkCacheTenantID, filename, data.(map[string][]CachedOAuth2Grant))
		wrapped = OAuth2GrantsCache{Data: merged}
	case "sp-approle-assignments.gob":
		merged := mergeDiskMap[[]CachedSPAppRoleAssignment](bulkCacheBaseDir, bulkCacheTenantID, filename, data.(map[string][]CachedSPAppRoleAssignment))
		wrapped = SPAppRoleAssignmentsCache{Data: merged}
	case "sign-in-activity.gob":
		merged := mergeDiskMap[SignInActivity](bulkCacheBaseDir, bulkCacheTenantID, filename, data.(map[string]SignInActivity))
		wrapped = SignInActivityCache{Data: merged}
	case "mfa-bulk.gob":
		merged := mergeDiskMap[MFAAuthenticationMethods](bulkCacheBaseDir, bulkCacheTenantID, filename, data.(map[string]MFAAuthenticationMethods))
		wrapped = MFABulkCache{Data: merged}
	case "pim-directory.gob":
		// PIM directory GOB stores both eligible and active. Rebuild full struct.
		dc := PIMDirectoryCache{}
		if eligible, found := AzureDataCache.Get(AzCacheKey("pim-dir-eligible-all", "tenant")); found {
			dc.Eligible = eligible.(map[string][]DirectoryRole)
		}
		if active, found := AzureDataCache.Get(AzCacheKey("pim-dir-active-all", "tenant")); found {
			dc.Active = active.(map[string][]DirectoryRole)
		}
		// Merge with disk for PIM directory
		var diskDC PIMDirectoryCache
		if loadPrefetchCache(bulkCacheBaseDir, bulkCacheTenantID, filename, DefaultAzureCacheExpiration, &diskDC) {
			if diskDC.Eligible != nil {
				for k, v := range dc.Eligible {
					diskDC.Eligible[k] = v
				}
				dc.Eligible = diskDC.Eligible
			}
			if diskDC.Active != nil {
				for k, v := range dc.Active {
					diskDC.Active[k] = v
				}
				dc.Active = diskDC.Active
			}
		}
		wrapped = dc
	default:
		return
	}

	savePrefetchCache(bulkCacheBaseDir, bulkCacheTenantID, filename, wrapped)
}

// mergeDiskMap loads the existing GOB from disk into a map, then overlays the
// in-memory entries on top. This ensures backfill entries from other processes
// are preserved. Returns the merged map. Caller must hold the file lock.
func mergeDiskMap[V any](baseDir, tenantID, filename string, memMap map[string]V) map[string]V {
	diskMap := loadDiskMapForMerge[V](baseDir, tenantID, filename)
	if diskMap == nil {
		return memMap
	}
	// Overlay in-memory entries (which are newer) onto the disk map
	for k, v := range memMap {
		diskMap[k] = v
	}
	return diskMap
}

// loadDiskMapForMerge loads the raw map from a GOB file for merging purposes.
// Returns nil if the file doesn't exist or can't be decoded.
func loadDiskMapForMerge[V any](baseDir, tenantID, filename string) map[string]V {
	switch filename {
	case "group-memberships.gob":
		var dc GroupMembershipsCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) && dc.Data != nil {
			return any(dc.Data).(map[string]V)
		}
	case "directory-role-members.gob":
		var dc DirectoryRoleMembersCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) && dc.Data != nil {
			return any(dc.Data).(map[string]V)
		}
	case "oauth2-grants.gob":
		var dc OAuth2GrantsCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) && dc.Data != nil {
			return any(dc.Data).(map[string]V)
		}
	case "sp-approle-assignments.gob":
		var dc SPAppRoleAssignmentsCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) && dc.Data != nil {
			return any(dc.Data).(map[string]V)
		}
	case "sign-in-activity.gob":
		var dc SignInActivityCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) && dc.Data != nil {
			return any(dc.Data).(map[string]V)
		}
	case "mfa-bulk.gob":
		var dc MFABulkCache
		if loadPrefetchCache(baseDir, tenantID, filename, DefaultAzureCacheExpiration, &dc) && dc.Data != nil {
			return any(dc.Data).(map[string]V)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Bulk cache completeness validation
// ---------------------------------------------------------------------------

// ValidateBulkCacheCompleteness compares bulk cache entry counts against the
// tenant principal counts loaded from the tenant cache. Logs a warning when a
// bulk cache covers significantly fewer principals than expected, which
// indicates the cache is stale relative to the tenant principal list.
//
// Call after EnsureBulkCacheLoaded or PreFetch to surface staleness early.
func ValidateBulkCacheCompleteness(tenantID string) {
	if globals.AZ_VERBOSITY < globals.AZ_VERBOSE_ERRORS {
		return
	}
	logger := internal.NewLogger()

	// Get tenant principal counts from in-memory cache
	var userCount, spCount, groupCount int
	for key, item := range AzureDataCache.Items() {
		switch {
		case strings.HasPrefix(key, "az-entra-users-"):
			if users, ok := item.Object.([]PrincipalInfo); ok {
				userCount = len(users)
			}
		case strings.HasPrefix(key, "az-service-principals-"):
			if sps, ok := item.Object.([]PrincipalInfo); ok {
				spCount = len(sps)
			}
		case strings.HasPrefix(key, "az-entra-groups-"):
			if groups, ok := item.Object.([]PrincipalInfo); ok {
				groupCount = len(groups)
			}
		}
	}

	totalPrincipals := userCount + spCount + groupCount
	if totalPrincipals == 0 {
		return // Tenant cache not loaded, nothing to compare against
	}

	// Check each bulk cache that maps principalID -> data
	checks := []struct {
		cacheKey     string
		description  string
		expectedBase int // which principal count to compare against
	}{
		{AzCacheKey("group-memberships-all", "tenant"), "group memberships", totalPrincipals},
		{AzCacheKey("sp-approle-assignments-all", "tenant"), "SP appRoleAssignments", spCount},
		{AzCacheKey("sign-in-activity-all", "tenant"), "sign-in activity", userCount},
	}

	for _, c := range checks {
		if c.expectedBase == 0 {
			continue
		}
		cached, found := AzureDataCache.Get(c.cacheKey)
		if !found {
			continue
		}

		mapLen := getBulkCacheMapLen(cached)
		if mapLen == 0 {
			continue
		}

		ratio := float64(mapLen) / float64(c.expectedBase)
		if ratio < 0.9 {
			logger.InfoM(fmt.Sprintf("Bulk cache %q has %d entries but tenant has %d principals (%.0f%%). Consider --refresh-cache.",
				c.description, mapLen, c.expectedBase, ratio*100), "cache")
		}
	}
}

// ---------------------------------------------------------------------------
// Per-subscription cache loading helpers
// ---------------------------------------------------------------------------

// EnsurePIMCacheLoaded loads PIM eligible + active caches from disk for a
// subscription if not already in memory. Sets bulk cache context for disk
// persistence.
func EnsurePIMCacheLoaded(baseDir, tenantID, subscriptionID string) {
	SetBulkCacheContext(baseDir, tenantID)
	eligibleKey := AzCacheKey("pim-eligible-all", subscriptionID)
	activeKey := AzCacheKey("pim-active-all", subscriptionID)

	_, eligibleFound := AzureDataCache.Get(eligibleKey)
	_, activeFound := AzureDataCache.Get(activeKey)
	if eligibleFound && activeFound {
		return
	}

	diskFile := fmt.Sprintf("pim-sub-%s.gob", subscriptionID)
	var dc PIMSubCache
	if loadPrefetchCache(baseDir, tenantID, diskFile, DefaultAzureCacheExpiration, &dc) {
		if dc.Eligible != nil {
			AzureDataCache.Set(eligibleKey, dc.Eligible, 0)
		}
		if dc.Active != nil {
			AzureDataCache.Set(activeKey, dc.Active, 0)
		}
	}
}

// EnsureRBACCacheLoaded loads RBAC scope caches from disk for a subscription
// if not already in memory. The GOB file contains a multi-scope map; each
// scope path is loaded as a separate in-memory cache entry.
func EnsureRBACCacheLoaded(baseDir, tenantID, subscriptionID string) {
	SetBulkCacheContext(baseDir, tenantID)

	// Check if the subscription scope is already loaded as a quick test
	subScope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	subKey := AzCacheKey("rbac-scope-all", subScope)
	if _, found := AzureDataCache.Get(subKey); found {
		return
	}

	diskFile := fmt.Sprintf("rbac-sub-%s.gob", subscriptionID)
	var dc RBACSubCache
	if loadPrefetchCache(baseDir, tenantID, diskFile, DefaultAzureCacheExpiration, &dc) {
		for scopePath, scopeMap := range dc.Scopes {
			cacheKey := AzCacheKey("rbac-scope-all", scopePath)
			AzureDataCache.Set(cacheKey, scopeMap, 0)
		}
	}
}

// getBulkCacheMapLen returns the length of a bulk cache map using type assertions.
func getBulkCacheMapLen(cached any) int {
	switch m := cached.(type) {
	case map[string]CachedGroupMembership:
		return len(m)
	case map[string][]DirectoryRole:
		return len(m)
	case map[string][]CachedOAuth2Grant:
		return len(m)
	case map[string][]CachedSPAppRoleAssignment:
		return len(m)
	case map[string]SignInActivity:
		return len(m)
	case map[string][]PIMRoleAssignment:
		return len(m)
	case map[string]MFAAuthenticationMethods:
		return len(m)
	default:
		return 0
	}
}
