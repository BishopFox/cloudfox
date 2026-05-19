package azure

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/cacheutil"
)

// ---------------------------------------------------------------------------
// Generic disk-cache helpers (GOB format, atomic write, age-based staleness)
// ---------------------------------------------------------------------------

// savePrefetchCache saves any GOB-encodable data to a cache file with atomic write.
func savePrefetchCache(baseDir, tenantID, filename string, data any) error {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	path := filepath.Join(cacheDir, filename)
	return cacheutil.AtomicWriteGob(path, data)
}

// loadPrefetchCache loads GOB data from a cache file into the target.
// Returns false if the file does not exist or cannot be decoded.
// Logs a warning if the cache is older than maxAge but still loads it.
// Caches are only invalidated by --refresh-cache, never by age alone.
func loadPrefetchCache(baseDir, tenantID, filename string, maxAge time.Duration, target any) bool {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	path := filepath.Join(cacheDir, filename)

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	age := time.Since(info.ModTime())
	if age > maxAge {
		logger := internal.NewLogger()
		logger.InfoM(fmt.Sprintf("Cache %s is stale (age: %s > %s). Use --refresh-cache to force update.",
			filename, FormatCacheAge(age), FormatCacheAge(maxAge)), "cache")
	}

	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	if err := gob.NewDecoder(file).Decode(target); err != nil {
		return false
	}
	return true
}

// FormatCacheAge formats a duration as a human-readable age string.
func FormatCacheAge(d time.Duration) string {
	hours := int(d.Hours())
	if hours < 24 {
		return fmt.Sprintf("%dh", hours)
	}
	days := hours / 24
	remaining := hours % 24
	if remaining == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, remaining)
}

// deletePrefetchCache removes a single cache file (best-effort).
func deletePrefetchCache(baseDir, tenantID, filename string) {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	os.Remove(filepath.Join(cacheDir, filename))
}

// deletePrefetchCacheGlob removes all cache files matching a glob pattern.
func deletePrefetchCacheGlob(baseDir, tenantID, pattern string) {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	matches, err := filepath.Glob(filepath.Join(cacheDir, pattern))
	if err != nil {
		return
	}
	for _, m := range matches {
		os.Remove(m)
	}
}

// ---------------------------------------------------------------------------
// Per-subscription PIM cache
// ---------------------------------------------------------------------------

// PIMSubCache stores pre-fetched PIM eligible + active role assignments for a subscription.
// Filename: pim-sub-{subscriptionID}.gob
type PIMSubCache struct {
	Eligible map[string][]PIMRoleAssignment // principalID -> assignments
	Active   map[string][]PIMRoleAssignment
}

// ---------------------------------------------------------------------------
// Per-subscription RBAC cache
// ---------------------------------------------------------------------------

// RBACSubCache stores pre-fetched RBAC role assignments across all scopes for a subscription.
// Filename: rbac-sub-{subscriptionID}.gob
type RBACSubCache struct {
	Scopes map[string]map[string][]cachedRBACRawAssignment // scopePath -> principalID -> assignments
}

// ---------------------------------------------------------------------------
// Tenant-level CA policies cache
// ---------------------------------------------------------------------------

// CAPoliciesCache stores pre-fetched conditional access policies (minimal, for per-principal matching).
// Filename: ca-policies.gob
type CAPoliciesCache struct {
	Policies []cachedCAPolicy
}

// CAPoliciesFullCache stores pre-fetched conditional access policies with full details.
// Filename: ca-policies-full.gob
type CAPoliciesFullCache struct {
	Policies []ConditionalAccessPolicyDetails
}

// ---------------------------------------------------------------------------
// Tenant-level PIM directory roles cache
// ---------------------------------------------------------------------------

// PIMDirectoryCache stores pre-fetched PIM eligible + active directory role assignments
// for all principals in the tenant.
// Filename: pim-directory.gob
type PIMDirectoryCache struct {
	Eligible map[string][]DirectoryRole // principalID -> roles
	Active   map[string][]DirectoryRole
}

// ---------------------------------------------------------------------------
// Tenant-level bulk group memberships cache
// ---------------------------------------------------------------------------

// CachedGroupMembership stores pre-computed group membership data for a principal.
type CachedGroupMembership struct {
	DirectGroupNames []string // display names of direct group memberships
	AllGroupNames    []string // display names of all group memberships (direct + nested)
	AllGroupIDs      []string // object IDs of all groups (for PIM principal ID expansion)
}

// GroupMembershipsCache stores bulk group membership data.
// Filename: group-memberships.gob
type GroupMembershipsCache struct {
	Data map[string]CachedGroupMembership // principalID -> membership data
}

// ---------------------------------------------------------------------------
// Tenant-level directory role members cache
// ---------------------------------------------------------------------------

// DirectoryRoleMembersCache stores pre-fetched directory role -> member mappings,
// inverted to principalID -> []DirectoryRole for O(1) lookup.
// Filename: directory-role-members.gob
type DirectoryRoleMembersCache struct {
	Data map[string][]DirectoryRole // principalID -> roles
}

// ---------------------------------------------------------------------------
// Tenant-level sign-in activity cache
// ---------------------------------------------------------------------------

// SignInActivityCache stores pre-fetched sign-in activity for all users.
// Filename: sign-in-activity.gob
type SignInActivityCache struct {
	Data map[string]SignInActivity // principalID -> activity
}

// ---------------------------------------------------------------------------
// Tenant-level OAuth2 grants cache
// ---------------------------------------------------------------------------

// CachedOAuth2Grant stores a single OAuth2 permission grant with resolved resource name.
type CachedOAuth2Grant struct {
	ClientID     string
	ConsentType  string
	ResourceName string
	Scopes       []string
}

// OAuth2GrantsCache stores all OAuth2 grants in the tenant.
// Filename: oauth2-grants.gob
type OAuth2GrantsCache struct {
	Data map[string][]CachedOAuth2Grant // clientID (principalID) -> grants
}

// ---------------------------------------------------------------------------
// Tenant-level SP appRoleAssignments cache
// ---------------------------------------------------------------------------

// CachedSPAppRoleAssignment stores a single resolved appRoleAssignment for a service principal.
type CachedSPAppRoleAssignment struct {
	ResourceDisplayName string
	AppRoleName         string
}

// SPAppRoleAssignmentsCache stores bulk SP appRoleAssignments for the entire tenant.
// Filename: sp-approle-assignments.gob
type SPAppRoleAssignmentsCache struct {
	Data map[string][]CachedSPAppRoleAssignment // spObjectID -> assignments
}

// ---------------------------------------------------------------------------
// Tenant-level bulk MFA cache
// ---------------------------------------------------------------------------

// MFABulkCache stores pre-fetched MFA authentication methods for all users.
// Filename: mfa-bulk.gob
type MFABulkCache struct {
	Data map[string]MFAAuthenticationMethods // userObjectID -> MFA data
}

// ---------------------------------------------------------------------------
// Deletion helpers
// ---------------------------------------------------------------------------

// DeleteAllPrefetchCaches removes all prefetch cache files for a tenant.
// Called on --refresh-cache.
func DeleteAllPrefetchCaches(baseDir, tenantID string) {
	deletePrefetchCacheGlob(baseDir, tenantID, "pim-sub-*.gob")
	deletePrefetchCacheGlob(baseDir, tenantID, "rbac-sub-*.gob")
	deletePrefetchCache(baseDir, tenantID, "ca-policies.gob")
	deletePrefetchCache(baseDir, tenantID, "ca-policies-full.gob")
	deletePrefetchCache(baseDir, tenantID, "pim-directory.gob")
	deletePrefetchCache(baseDir, tenantID, "mfa-bulk.gob")
	deletePrefetchCache(baseDir, tenantID, "group-memberships.gob")
	deletePrefetchCache(baseDir, tenantID, "group-memberships-partial.gob")
	deletePrefetchCache(baseDir, tenantID, "directory-role-members.gob")
	deletePrefetchCache(baseDir, tenantID, "sign-in-activity.gob")
	deletePrefetchCache(baseDir, tenantID, "oauth2-grants.gob")
	deletePrefetchCache(baseDir, tenantID, "sp-approle-assignments.gob")
}
