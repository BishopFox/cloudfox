package gcpinternal

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheExpiration is the default time after which cache is considered stale
// and will be automatically refreshed
const DefaultCacheExpiration = 24 * time.Hour

// atomicWriteGob writes data to a file atomically using a temp file and rename
// This prevents corruption if the process is interrupted during write
func atomicWriteGob(filename string, data interface{}) error {
	// Create temp file in the same directory (required for atomic rename)
	dir := filepath.Dir(filename)
	tempFile, err := os.CreateTemp(dir, ".tmp-*.gob")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempName := tempFile.Name()

	// Ensure cleanup on failure
	success := false
	defer func() {
		if !success {
			tempFile.Close()
			os.Remove(tempName)
		}
	}()

	// Encode to temp file
	encoder := gob.NewEncoder(tempFile)
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode data: %w", err)
	}

	// Sync to ensure data is written to disk
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	// Close before rename
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempName, filename); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	success = true
	return nil
}

// atomicWriteFile writes data to a file atomically
func atomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	tempFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempName := tempFile.Name()

	success := false
	defer func() {
		if !success {
			tempFile.Close()
			os.Remove(tempName)
		}
	}()

	if _, err := io.WriteString(tempFile, string(data)); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	if err := tempFile.Chmod(perm); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close: %w", err)
	}

	if err := os.Rename(tempName, filename); err != nil {
		return fmt.Errorf("failed to rename: %w", err)
	}

	success = true
	return nil
}

// CacheMetadata holds information about when the cache was created
type CacheMetadata struct {
	CreatedAt     time.Time `json:"created_at"`
	Account       string    `json:"account"`
	Version       string    `json:"version"`
	ProjectsIn    []string  `json:"projects_in,omitempty"`    // Projects used when creating cache
	TotalProjects int       `json:"total_projects,omitempty"` // Total projects in org (for org cache)
}

// PersistentOrgCache is the serializable version of OrgCache
type PersistentOrgCache struct {
	Metadata      CacheMetadata        `json:"metadata"`
	Organizations []CachedOrganization `json:"organizations"`
	Folders       []CachedFolder       `json:"folders"`
	AllProjects   []CachedProject      `json:"all_projects"`
}

// GetCacheDirectory returns the cache directory for a given account
func GetCacheDirectory(baseDir, account string) string {
	// Sanitize account email for use in path
	sanitized := sanitizeForPath(account)
	return filepath.Join(baseDir, "cached-data", "gcp", sanitized)
}

// sanitizeForPath removes/replaces characters that are problematic in file paths
func sanitizeForPath(s string) string {
	// Replace @ and other special chars with underscores
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// OrgCacheFilename returns the filename for org cache
func OrgCacheFilename() string {
	return "org-cache.gob"
}

// SaveOrgCacheToFile saves the org cache to a gob file using atomic write
func SaveOrgCacheToFile(cache *OrgCache, baseDir, account, version string) error {
	cacheDir := GetCacheDirectory(baseDir, account)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	persistent := PersistentOrgCache{
		Metadata: CacheMetadata{
			CreatedAt:     time.Now(),
			Account:       account,
			Version:       version,
			TotalProjects: len(cache.AllProjects),
		},
		Organizations: cache.Organizations,
		Folders:       cache.Folders,
		AllProjects:   cache.AllProjects,
	}

	filename := filepath.Join(cacheDir, OrgCacheFilename())

	// Use atomic write: write to temp file, then rename
	if err := atomicWriteGob(filename, persistent); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	// Also save JSON for debugging/inspection
	jsonFilename := filepath.Join(cacheDir, "org-cache.json")
	jsonData, err := json.MarshalIndent(persistent, "", "  ")
	if err == nil {
		atomicWriteFile(jsonFilename, jsonData, 0644)
	}

	return nil
}

// LoadOrgCacheFromFile loads the org cache from a gob file
func LoadOrgCacheFromFile(baseDir, account string) (*OrgCache, *CacheMetadata, error) {
	cacheDir := GetCacheDirectory(baseDir, account)
	filename := filepath.Join(cacheDir, OrgCacheFilename())

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil // Cache doesn't exist, not an error
		}
		return nil, nil, fmt.Errorf("failed to open cache file: %w", err)
	}
	defer file.Close()

	var persistent PersistentOrgCache
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&persistent); err != nil {
		return nil, nil, fmt.Errorf("failed to decode cache: %w", err)
	}

	// Convert to in-memory cache
	cache := NewOrgCache()
	for _, org := range persistent.Organizations {
		cache.AddOrganization(org)
	}
	for _, folder := range persistent.Folders {
		cache.AddFolder(folder)
	}
	for _, project := range persistent.AllProjects {
		cache.AddProject(project)
	}
	cache.MarkPopulated()

	return cache, &persistent.Metadata, nil
}

// OrgCacheExists checks if an org cache file exists
func OrgCacheExists(baseDir, account string) bool {
	cacheDir := GetCacheDirectory(baseDir, account)
	filename := filepath.Join(cacheDir, OrgCacheFilename())
	_, err := os.Stat(filename)
	return err == nil
}

// GetCacheAge returns how old a cache file is
func GetCacheAge(baseDir, account, cacheType string) (time.Duration, error) {
	cacheDir := GetCacheDirectory(baseDir, account)
	var filename string
	switch cacheType {
	case "org":
		filename = filepath.Join(cacheDir, OrgCacheFilename())
	default:
		return 0, fmt.Errorf("unknown cache type: %s", cacheType)
	}

	info, err := os.Stat(filename)
	if err != nil {
		return 0, err
	}

	return time.Since(info.ModTime()), nil
}

// IsCacheStale checks if a cache is older than the given duration
func IsCacheStale(baseDir, account, cacheType string, maxAge time.Duration) bool {
	age, err := GetCacheAge(baseDir, account, cacheType)
	if err != nil {
		return true // If we can't determine age, consider it stale
	}
	return age > maxAge
}

// DeleteCache removes a cache file
func DeleteCache(baseDir, account, cacheType string) error {
	cacheDir := GetCacheDirectory(baseDir, account)
	var filename string
	switch cacheType {
	case "org":
		filename = filepath.Join(cacheDir, OrgCacheFilename())
		// Also remove JSON
		os.Remove(filepath.Join(cacheDir, "org-cache.json"))
	default:
		return fmt.Errorf("unknown cache type: %s", cacheType)
	}

	return os.Remove(filename)
}
