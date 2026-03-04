package gcpinternal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// GCPCloudIPRangesURL is the public Google endpoint that lists all GCP regions
// This endpoint requires no authentication and is updated by Google
const GCPCloudIPRangesURL = "https://www.gstatic.com/ipranges/cloud.json"

// cloudIPRangesResponse represents the JSON structure from cloud.json
type cloudIPRangesResponse struct {
	SyncToken    string        `json:"syncToken"`
	CreationTime string        `json:"creationTime"`
	Prefixes     []cloudPrefix `json:"prefixes"`
}

// cloudPrefix represents a single IP prefix entry
type cloudPrefix struct {
	IPv4Prefix string `json:"ipv4Prefix,omitempty"`
	IPv6Prefix string `json:"ipv6Prefix,omitempty"`
	Service    string `json:"service"`
	Scope      string `json:"scope"`
}

// cachedRegions holds the cached region list with expiration
var (
	cachedRegions     []string
	cachedZones       []string
	regionsCacheTime  time.Time
	regionsCacheMutex sync.RWMutex
	regionsCacheTTL   = 24 * time.Hour
)

// GetGCPRegions returns a list of all GCP regions from the public cloud.json endpoint
// This does not require any GCP authentication or permissions
// Results are cached for 24 hours
func GetGCPRegions() ([]string, error) {
	regionsCacheMutex.RLock()
	if len(cachedRegions) > 0 && time.Since(regionsCacheTime) < regionsCacheTTL {
		regions := make([]string, len(cachedRegions))
		copy(regions, cachedRegions)
		regionsCacheMutex.RUnlock()
		return regions, nil
	}
	regionsCacheMutex.RUnlock()

	// Fetch fresh data
	regions, err := fetchGCPRegionsFromPublicEndpoint()
	if err != nil {
		return nil, err
	}

	// Cache the results
	regionsCacheMutex.Lock()
	cachedRegions = regions
	regionsCacheTime = time.Now()
	regionsCacheMutex.Unlock()

	return regions, nil
}

// fetchGCPRegionsFromPublicEndpoint fetches regions from the public Google endpoint
func fetchGCPRegionsFromPublicEndpoint() ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(GCPCloudIPRangesURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GCP regions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch GCP regions: HTTP %d", resp.StatusCode)
	}

	var data cloudIPRangesResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse GCP regions response: %w", err)
	}

	// Extract unique regions from scopes
	regionSet := make(map[string]bool)
	for _, prefix := range data.Prefixes {
		scope := prefix.Scope
		// Skip global and empty scopes
		if scope == "" || scope == "global" {
			continue
		}
		// Only include scopes that look like regions (contain a hyphen and number)
		if strings.Contains(scope, "-") && containsDigit(scope) {
			regionSet[scope] = true
		}
	}

	// Convert to sorted slice
	regions := make([]string, 0, len(regionSet))
	for region := range regionSet {
		regions = append(regions, region)
	}
	sort.Strings(regions)

	return regions, nil
}

// GetGCPZonesForRegion returns common zone suffixes for a region
// GCP zones are typically region + letter suffix (a, b, c, d, etc.)
func GetGCPZonesForRegion(region string) []string {
	// Most regions have zones a, b, c; some have more
	commonSuffixes := []string{"a", "b", "c", "d", "f"}
	zones := make([]string, len(commonSuffixes))
	for i, suffix := range commonSuffixes {
		zones[i] = region + "-" + suffix
	}
	return zones
}

// GetAllGCPZones returns all possible zones for all regions
// This is a best-effort list based on common zone naming patterns
func GetAllGCPZones() ([]string, error) {
	regions, err := GetGCPRegions()
	if err != nil {
		return nil, err
	}

	var zones []string
	for _, region := range regions {
		zones = append(zones, GetGCPZonesForRegion(region)...)
	}
	return zones, nil
}

// containsDigit checks if a string contains at least one digit
func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// CommonGCPRegions is a hardcoded fallback list of common GCP regions
// Used if the public endpoint is unavailable
var CommonGCPRegions = []string{
	"africa-south1",
	"asia-east1",
	"asia-east2",
	"asia-northeast1",
	"asia-northeast2",
	"asia-northeast3",
	"asia-south1",
	"asia-south2",
	"asia-southeast1",
	"asia-southeast2",
	"australia-southeast1",
	"australia-southeast2",
	"europe-central2",
	"europe-north1",
	"europe-southwest1",
	"europe-west1",
	"europe-west2",
	"europe-west3",
	"europe-west4",
	"europe-west6",
	"europe-west8",
	"europe-west9",
	"europe-west10",
	"europe-west12",
	"me-central1",
	"me-central2",
	"me-west1",
	"northamerica-northeast1",
	"northamerica-northeast2",
	"southamerica-east1",
	"southamerica-west1",
	"us-central1",
	"us-east1",
	"us-east4",
	"us-east5",
	"us-south1",
	"us-west1",
	"us-west2",
	"us-west3",
	"us-west4",
}

// GetGCPRegionsWithFallback returns regions from the public endpoint,
// falling back to the hardcoded list if the endpoint is unavailable
func GetGCPRegionsWithFallback() []string {
	regions, err := GetGCPRegions()
	if err != nil || len(regions) == 0 {
		return CommonGCPRegions
	}
	return regions
}
