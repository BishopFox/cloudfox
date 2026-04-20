package azure

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BishopFox/cloudfox/internal/cacheutil"
)

// DefaultAzureCacheExpiration is the time after which the disk cache is considered stale.
const DefaultAzureCacheExpiration = 24 * time.Hour

// ---- Persistent (disk) cache ----

// TenantCacheMetadata holds information about when and how the cache was created.
type TenantCacheMetadata struct {
	CreatedAt   time.Time `json:"created_at"`
	TenantID    string    `json:"tenant_id"`
	TenantName  string    `json:"tenant_name,omitempty"`
	Version     string    `json:"version"`
	TotalUsers  int       `json:"total_users"`
	TotalSPs    int       `json:"total_service_principals"`
	TotalGroups int       `json:"total_groups"`
}

// PersistentTenantCache is the serializable version of tenant cache data.
type PersistentTenantCache struct {
	Metadata          TenantCacheMetadata `json:"metadata"`
	Users             []PrincipalInfo     `json:"users"`
	ServicePrincipals []PrincipalInfo     `json:"service_principals"`
	Groups            []PrincipalInfo     `json:"groups"`
}

// GetAzureCacheDirectory returns the cache directory for a given tenant.
// Layout: $baseDir/cached-data/azure/<tenant-id>/
func GetAzureCacheDirectory(baseDir, tenantID string) string {
	sanitized := cacheutil.SanitizeForPath(tenantID)
	return filepath.Join(baseDir, "cached-data", "azure", sanitized)
}

// TenantCacheFilename returns the filename for the tenant cache GOB file.
func TenantCacheFilename() string {
	return "tenant-cache.gob"
}

// SaveTenantCacheToFile saves tenant cache data to disk using atomic write.
func SaveTenantCacheToFile(users, sps, groups []PrincipalInfo, baseDir, tenantID, tenantName, version string) error {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	persistent := PersistentTenantCache{
		Metadata: TenantCacheMetadata{
			CreatedAt:   time.Now(),
			TenantID:    tenantID,
			TenantName:  tenantName,
			Version:     version,
			TotalUsers:  len(users),
			TotalSPs:    len(sps),
			TotalGroups: len(groups),
		},
		Users:             users,
		ServicePrincipals: sps,
		Groups:            groups,
	}

	filename := filepath.Join(cacheDir, TenantCacheFilename())

	if err := cacheutil.AtomicWriteGob(filename, persistent); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	// Also save JSON for debugging/inspection
	jsonFilename := filepath.Join(cacheDir, "tenant-cache.json")
	jsonData, err := json.MarshalIndent(persistent, "", "  ")
	if err == nil {
		cacheutil.AtomicWriteFile(jsonFilename, jsonData, 0644)
	}

	return nil
}

// LoadTenantCacheFromFile loads the tenant cache from a GOB file on disk.
func LoadTenantCacheFromFile(baseDir, tenantID string) (users, sps, groups []PrincipalInfo, metadata *TenantCacheMetadata, err error) {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	filename := filepath.Join(cacheDir, TenantCacheFilename())

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil, nil, nil // Cache doesn't exist, not an error
		}
		return nil, nil, nil, nil, fmt.Errorf("failed to open cache file: %w", err)
	}
	defer file.Close()

	var persistent PersistentTenantCache
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&persistent); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode cache: %w", err)
	}

	return persistent.Users, persistent.ServicePrincipals, persistent.Groups, &persistent.Metadata, nil
}

// TenantCacheExists checks if a tenant cache file exists on disk.
func TenantCacheExists(baseDir, tenantID string) bool {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	filename := filepath.Join(cacheDir, TenantCacheFilename())
	_, err := os.Stat(filename)
	return err == nil
}

// GetTenantCacheAge returns how old the tenant cache file is.
func GetTenantCacheAge(baseDir, tenantID string) (time.Duration, error) {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	filename := filepath.Join(cacheDir, TenantCacheFilename())

	info, err := os.Stat(filename)
	if err != nil {
		return 0, err
	}

	return time.Since(info.ModTime()), nil
}

// IsTenantCacheStale checks if the tenant cache is older than maxAge.
func IsTenantCacheStale(baseDir, tenantID string, maxAge time.Duration) bool {
	age, err := GetTenantCacheAge(baseDir, tenantID)
	if err != nil {
		return true // If we can't determine age, consider it stale
	}
	return age > maxAge
}

// DeleteTenantCache removes the tenant cache files from disk.
func DeleteTenantCache(baseDir, tenantID string) error {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	gobFile := filepath.Join(cacheDir, TenantCacheFilename())
	jsonFile := filepath.Join(cacheDir, "tenant-cache.json")

	os.Remove(jsonFile) // best-effort
	return os.Remove(gobFile)
}

