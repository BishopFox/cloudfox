package azure

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// enrichmentCacheFilename is the JSONL file for per-principal enrichment cache.
const enrichmentCacheFilename = "principals-enrichment.jsonl"

// EnrichmentCacheEntry represents one JSON line per enriched principal.
type EnrichmentCacheEntry struct {
	PrincipalID string   `json:"principal_id"`
	Row         []string `json:"row"`
	Loot        string   `json:"loot"`
	Timestamp   int64    `json:"ts"`
}

// EnrichmentCacheWriter is a thread-safe JSONL appender (opened once, shared across goroutines).
type EnrichmentCacheWriter struct {
	mu   sync.Mutex
	file *os.File
}

// EnrichmentCacheResult holds loaded state from JSONL for resume.
type EnrichmentCacheResult struct {
	SkipSet map[string]bool
	Rows    [][]string
	Loot    string
	Count   int
}

// EnrichmentCacheFilePath returns the path to the JSONL enrichment cache file.
func EnrichmentCacheFilePath(baseDir, tenantID string) string {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	return filepath.Join(cacheDir, enrichmentCacheFilename)
}

// LoadEnrichmentCache reads the JSONL file, deduplicates by PrincipalID (last-wins),
// and builds a skip-set, rows, and concatenated loot string.
// Returns nil, nil if the file doesn't exist or is empty.
func LoadEnrichmentCache(baseDir, tenantID string) (*EnrichmentCacheResult, error) {
	path := EnrichmentCacheFilePath(baseDir, tenantID)

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open enrichment cache: %w", err)
	}
	defer file.Close()

	// Dedup map: principalID -> entry (last-wins)
	seen := make(map[string]EnrichmentCacheEntry)
	// Track insertion order for stable row ordering
	order := []string{}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 256*1024), 256*1024) // 256KB buffer for large rows

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry EnrichmentCacheEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			// Silently skip corrupt/incomplete lines (crash resilience)
			continue
		}
		if entry.PrincipalID == "" {
			continue
		}

		if _, exists := seen[entry.PrincipalID]; !exists {
			order = append(order, entry.PrincipalID)
		}
		seen[entry.PrincipalID] = entry
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading enrichment cache: %w", err)
	}

	if len(seen) == 0 {
		return nil, nil
	}

	result := &EnrichmentCacheResult{
		SkipSet: make(map[string]bool, len(seen)),
		Rows:    make([][]string, 0, len(seen)),
		Count:   len(seen),
	}

	var lootBuilder []byte
	for _, pid := range order {
		entry := seen[pid]
		result.SkipSet[pid] = true
		result.Rows = append(result.Rows, entry.Row)
		if entry.Loot != "" {
			lootBuilder = append(lootBuilder, entry.Loot...)
		}
	}
	result.Loot = string(lootBuilder)

	return result, nil
}

// NewEnrichmentCacheWriter opens the JSONL file for append and returns a writer.
// Creates the directory if it doesn't exist.
func NewEnrichmentCacheWriter(baseDir, tenantID string) (*EnrichmentCacheWriter, error) {
	path := EnrichmentCacheFilePath(baseDir, tenantID)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create enrichment cache directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open enrichment cache for writing: %w", err)
	}

	return &EnrichmentCacheWriter{file: file}, nil
}

// Append writes a single cache entry as a JSON line. Accepts any JSON-serializable value.
func (w *EnrichmentCacheWriter) Append(entry any) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal enrichment cache entry: %w", err)
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	_, err = w.file.Write(data)
	return err
}

// Close closes the underlying file.
func (w *EnrichmentCacheWriter) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// EnrichmentCacheExists checks if the enrichment cache file exists on disk.
func EnrichmentCacheExists(baseDir, tenantID string) bool {
	_, err := os.Stat(EnrichmentCacheFilePath(baseDir, tenantID))
	return err == nil
}

// GetEnrichmentCacheAge returns how old the enrichment cache file is.
func GetEnrichmentCacheAge(baseDir, tenantID string) (time.Duration, error) {
	info, err := os.Stat(EnrichmentCacheFilePath(baseDir, tenantID))
	if err != nil {
		return 0, err
	}
	return time.Since(info.ModTime()), nil
}

// IsEnrichmentCacheStale checks if the enrichment cache is older than maxAge.
func IsEnrichmentCacheStale(baseDir, tenantID string, maxAge time.Duration) bool {
	age, err := GetEnrichmentCacheAge(baseDir, tenantID)
	if err != nil {
		return true // If we can't determine age, consider it stale
	}
	return age > maxAge
}

// DeleteEnrichmentCache removes the enrichment cache file from disk.
func DeleteEnrichmentCache(baseDir, tenantID string) error {
	return os.Remove(EnrichmentCacheFilePath(baseDir, tenantID))
}

// ========================================
// Generic JSONL writer constructor
// ========================================

// NewJSONLWriter opens a JSONL file at the given path for append and returns a writer.
// Creates the parent directory if it doesn't exist.
func NewJSONLWriter(path string) (*EnrichmentCacheWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open JSONL file for writing: %w", err)
	}

	return &EnrichmentCacheWriter{file: file}, nil
}

// ========================================
// Permissions enrichment cache
// ========================================

const permEnrichmentCacheFilename = "permissions-enrichment.jsonl"

// PermEnrichmentCacheEntry represents one JSON line per enriched principal (multi-row).
type PermEnrichmentCacheEntry struct {
	PrincipalID string     `json:"principal_id"`
	Rows        [][]string `json:"rows"`
	Timestamp   int64      `json:"ts"`
}

// PermEnrichmentCacheResult holds loaded state from JSONL for resume.
type PermEnrichmentCacheResult struct {
	SkipSet map[string]bool
	Rows    [][]string
	Count   int
}

// PermEnrichmentCacheFilePath returns the path to the permissions JSONL enrichment cache file.
func PermEnrichmentCacheFilePath(baseDir, tenantID string) string {
	cacheDir := GetAzureCacheDirectory(baseDir, tenantID)
	return filepath.Join(cacheDir, permEnrichmentCacheFilename)
}

// LoadPermEnrichmentCache reads the permissions JSONL file, deduplicates by PrincipalID (last-wins),
// and builds a skip-set and flattened rows slice.
// Returns nil, nil if the file doesn't exist or is empty.
func LoadPermEnrichmentCache(baseDir, tenantID string) (*PermEnrichmentCacheResult, error) {
	path := PermEnrichmentCacheFilePath(baseDir, tenantID)

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open permissions enrichment cache: %w", err)
	}
	defer file.Close()

	// Dedup map: principalID -> entry (last-wins)
	seen := make(map[string]PermEnrichmentCacheEntry)
	// Track insertion order for stable row ordering
	order := []string{}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer (permissions rows can be large)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry PermEnrichmentCacheEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			// Silently skip corrupt/incomplete lines (crash resilience)
			continue
		}
		if entry.PrincipalID == "" {
			continue
		}

		if _, exists := seen[entry.PrincipalID]; !exists {
			order = append(order, entry.PrincipalID)
		}
		seen[entry.PrincipalID] = entry
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading permissions enrichment cache: %w", err)
	}

	if len(seen) == 0 {
		return nil, nil
	}

	result := &PermEnrichmentCacheResult{
		SkipSet: make(map[string]bool, len(seen)),
		Count:   len(seen),
	}

	// Flatten all rows
	for _, pid := range order {
		entry := seen[pid]
		result.SkipSet[pid] = true
		result.Rows = append(result.Rows, entry.Rows...)
	}

	return result, nil
}

// PermEnrichmentCacheExists checks if the permissions enrichment cache file exists on disk.
func PermEnrichmentCacheExists(baseDir, tenantID string) bool {
	_, err := os.Stat(PermEnrichmentCacheFilePath(baseDir, tenantID))
	return err == nil
}

// GetPermEnrichmentCacheAge returns how old the permissions enrichment cache file is.
func GetPermEnrichmentCacheAge(baseDir, tenantID string) (time.Duration, error) {
	info, err := os.Stat(PermEnrichmentCacheFilePath(baseDir, tenantID))
	if err != nil {
		return 0, err
	}
	return time.Since(info.ModTime()), nil
}

// IsPermEnrichmentCacheStale checks if the permissions enrichment cache is older than maxAge.
func IsPermEnrichmentCacheStale(baseDir, tenantID string, maxAge time.Duration) bool {
	age, err := GetPermEnrichmentCacheAge(baseDir, tenantID)
	if err != nil {
		return true // If we can't determine age, consider it stale
	}
	return age > maxAge
}

// DeletePermEnrichmentCache removes the permissions enrichment cache file from disk.
func DeletePermEnrichmentCache(baseDir, tenantID string) error {
	return os.Remove(PermEnrichmentCacheFilePath(baseDir, tenantID))
}
