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

// RoleDefinitionCacheExpiration is the time after which the role definition disk cache is stale.
// Role definitions (both built-in and custom) change very rarely, so 7 days is safe.
const RoleDefinitionCacheExpiration = 7 * 24 * time.Hour

// RoleDefinitionCacheMetadata holds information about when and how the cache was created.
type RoleDefinitionCacheMetadata struct {
	CreatedAt time.Time `json:"created_at"`
	TenantID  string    `json:"tenant_id"`
	Version   string    `json:"version"`
	TotalDefs int       `json:"total_definitions"`
}

// PersistentRoleDefinitionCache is the serializable version of role definition cache data.
type PersistentRoleDefinitionCache struct {
	Metadata    RoleDefinitionCacheMetadata `json:"metadata"`
	Definitions map[string]string          `json:"definitions"` // roleDefinitionID -> roleName
}

// RoleDefinitionCacheFilename returns the filename for the role definition cache GOB file.
func RoleDefinitionCacheFilename() string {
	return "role-definitions.gob"
}

// SaveRoleDefinitionCache saves role definition mappings to disk using atomic write.
func SaveRoleDefinitionCache(defs map[string]string, baseDir, tenantID string) error {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	persistent := PersistentRoleDefinitionCache{
		Metadata: RoleDefinitionCacheMetadata{
			CreatedAt: time.Now(),
			TenantID:  tenantID,
			Version:   "1.0.0",
			TotalDefs: len(defs),
		},
		Definitions: defs,
	}

	filename := filepath.Join(cacheDir, RoleDefinitionCacheFilename())

	if err := cacheutil.AtomicWriteGob(filename, persistent); err != nil {
		return fmt.Errorf("failed to write role definition cache: %w", err)
	}

	// Also save JSON for debugging/inspection
	jsonFilename := filepath.Join(cacheDir, "role-definitions.json")
	jsonData, err := json.MarshalIndent(persistent, "", "  ")
	if err == nil {
		cacheutil.AtomicWriteFile(jsonFilename, jsonData, 0644)
	}

	return nil
}

// LoadRoleDefinitionCache loads role definition mappings from a GOB file on disk.
// Returns an empty map (not an error) if the file does not exist.
func LoadRoleDefinitionCache(baseDir, tenantID string) (map[string]string, *RoleDefinitionCacheMetadata, error) {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	filename := filepath.Join(cacheDir, RoleDefinitionCacheFilename())

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil // Cache doesn't exist, not an error
		}
		return nil, nil, fmt.Errorf("failed to open role definition cache: %w", err)
	}
	defer file.Close()

	var persistent PersistentRoleDefinitionCache
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&persistent); err != nil {
		return nil, nil, fmt.Errorf("failed to decode role definition cache: %w", err)
	}

	return persistent.Definitions, &persistent.Metadata, nil
}

// RoleDefinitionCacheExists checks if a role definition cache file exists on disk.
func RoleDefinitionCacheExists(baseDir, tenantID string) bool {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	filename := filepath.Join(cacheDir, RoleDefinitionCacheFilename())
	_, err := os.Stat(filename)
	return err == nil
}

// GetRoleDefinitionCacheAge returns how old the role definition cache file is.
func GetRoleDefinitionCacheAge(baseDir, tenantID string) (time.Duration, error) {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	filename := filepath.Join(cacheDir, RoleDefinitionCacheFilename())

	info, err := os.Stat(filename)
	if err != nil {
		return 0, err
	}

	return time.Since(info.ModTime()), nil
}

// IsRoleDefinitionCacheStale checks if the role definition cache is older than maxAge.
func IsRoleDefinitionCacheStale(baseDir, tenantID string, maxAge time.Duration) bool {
	age, err := GetRoleDefinitionCacheAge(baseDir, tenantID)
	if err != nil {
		return true // If we can't determine age, consider it stale
	}
	return age > maxAge
}

// DeleteRoleDefinitionCache removes the role definition cache files from disk.
func DeleteRoleDefinitionCache(baseDir, tenantID string) error {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	gobFile := filepath.Join(cacheDir, RoleDefinitionCacheFilename())
	jsonFile := filepath.Join(cacheDir, "role-definitions.json")

	os.Remove(jsonFile) // best-effort
	return os.Remove(gobFile)
}
