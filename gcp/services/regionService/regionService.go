// Package regionservice provides a unified way to enumerate GCP regions and zones
// with automatic fallback when permissions are denied.
//
// Fallback order:
// 1. Try Compute Engine Regions.List API (requires compute.regions.list)
// 2. Fall back to public Google endpoint (no auth required)
// 3. Fall back to hardcoded common regions list
package regionservice

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/api/compute/v1"
)

// GCPCloudIPRangesURL is the public Google endpoint that lists all GCP regions
// This endpoint requires no authentication and is updated by Google
const GCPCloudIPRangesURL = "https://www.gstatic.com/ipranges/cloud.json"

// RegionService provides methods to enumerate GCP regions and zones
type RegionService struct {
	computeService *compute.Service
	httpClient     *http.Client
}

// RegionInfo contains information about a GCP region
type RegionInfo struct {
	Name   string   // Region name (e.g., "us-central1")
	Zones  []string // Available zones in this region
	Status string   // Region status (UP, DOWN, or unknown)
}

// New creates a new RegionService
func New() *RegionService {
	return &RegionService{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// NewWithComputeService creates a RegionService with an existing compute service
func NewWithComputeService(svc *compute.Service) *RegionService {
	return &RegionService{
		computeService: svc,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
	}
}

// GetRegions returns all GCP regions with automatic fallback
// Tries in order: Compute API -> Public endpoint -> Hardcoded list
func (s *RegionService) GetRegions(ctx context.Context, projectID string) ([]RegionInfo, error) {
	// Try Compute Engine API first (most accurate, includes zones)
	if projectID != "" {
		regions, err := s.getRegionsFromComputeAPI(ctx, projectID)
		if err == nil && len(regions) > 0 {
			return regions, nil
		}
		// Log but continue to fallback
	}

	// Fall back to public endpoint
	regions, err := s.getRegionsFromPublicEndpoint()
	if err == nil && len(regions) > 0 {
		return regions, nil
	}

	// Fall back to hardcoded list
	return s.getHardcodedRegions(), nil
}

// GetRegionNames returns just the region names (convenience method)
func (s *RegionService) GetRegionNames(ctx context.Context, projectID string) []string {
	regions, _ := s.GetRegions(ctx, projectID)
	names := make([]string, len(regions))
	for i, r := range regions {
		names[i] = r.Name
	}
	return names
}

// GetAllZones returns all zones across all regions
func (s *RegionService) GetAllZones(ctx context.Context, projectID string) []string {
	regions, _ := s.GetRegions(ctx, projectID)
	var zones []string
	for _, r := range regions {
		zones = append(zones, r.Zones...)
	}
	return zones
}

// getRegionsFromComputeAPI tries to get regions from the Compute Engine API
func (s *RegionService) getRegionsFromComputeAPI(ctx context.Context, projectID string) ([]RegionInfo, error) {
	svc := s.computeService
	if svc == nil {
		var err error
		svc, err = compute.NewService(ctx)
		if err != nil {
			return nil, err
		}
	}

	resp, err := svc.Regions.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	regions := make([]RegionInfo, 0, len(resp.Items))
	for _, r := range resp.Items {
		info := RegionInfo{
			Name:   r.Name,
			Status: r.Status,
			Zones:  make([]string, 0, len(r.Zones)),
		}
		for _, zoneURL := range r.Zones {
			// Extract zone name from URL
			parts := strings.Split(zoneURL, "/")
			if len(parts) > 0 {
				info.Zones = append(info.Zones, parts[len(parts)-1])
			}
		}
		regions = append(regions, info)
	}

	return regions, nil
}

// cloudIPRangesResponse represents the JSON structure from cloud.json
type cloudIPRangesResponse struct {
	SyncToken    string        `json:"syncToken"`
	CreationTime string        `json:"creationTime"`
	Prefixes     []cloudPrefix `json:"prefixes"`
}

type cloudPrefix struct {
	IPv4Prefix string `json:"ipv4Prefix,omitempty"`
	IPv6Prefix string `json:"ipv6Prefix,omitempty"`
	Service    string `json:"service"`
	Scope      string `json:"scope"`
}

// getRegionsFromPublicEndpoint fetches regions from the public Google endpoint
func (s *RegionService) getRegionsFromPublicEndpoint() ([]RegionInfo, error) {
	resp, err := s.httpClient.Get(GCPCloudIPRangesURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data cloudIPRangesResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	// Extract unique regions
	regionSet := make(map[string]bool)
	for _, prefix := range data.Prefixes {
		scope := prefix.Scope
		if scope == "" || scope == "global" {
			continue
		}
		if strings.Contains(scope, "-") && containsDigit(scope) {
			regionSet[scope] = true
		}
	}

	// Convert to RegionInfo with generated zones
	regions := make([]RegionInfo, 0, len(regionSet))
	for region := range regionSet {
		info := RegionInfo{
			Name:   region,
			Status: "unknown",
			Zones:  generateZonesForRegion(region),
		}
		regions = append(regions, info)
	}

	// Sort by name
	sort.Slice(regions, func(i, j int) bool {
		return regions[i].Name < regions[j].Name
	})

	return regions, nil
}

// getHardcodedRegions returns a hardcoded list of common GCP regions
func (s *RegionService) getHardcodedRegions() []RegionInfo {
	regions := make([]RegionInfo, len(commonGCPRegions))
	for i, name := range commonGCPRegions {
		regions[i] = RegionInfo{
			Name:   name,
			Status: "unknown",
			Zones:  generateZonesForRegion(name),
		}
	}
	return regions
}

// generateZonesForRegion generates common zone names for a region
func generateZonesForRegion(region string) []string {
	// Most regions have zones a, b, c; some have more
	suffixes := []string{"a", "b", "c"}
	zones := make([]string, len(suffixes))
	for i, suffix := range suffixes {
		zones[i] = region + "-" + suffix
	}
	return zones
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

// commonGCPRegions is a hardcoded fallback list of common GCP regions
var commonGCPRegions = []string{
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

// ---- Cached singleton for convenience ----

var (
	defaultService     *RegionService
	defaultServiceOnce sync.Once
	cachedRegions      []RegionInfo
	cachedRegionsMu    sync.RWMutex
	cacheTime          time.Time
	cacheTTL           = 1 * time.Hour
)

// GetDefaultService returns a singleton RegionService
func GetDefaultService() *RegionService {
	defaultServiceOnce.Do(func() {
		defaultService = New()
	})
	return defaultService
}

// GetCachedRegions returns cached regions, refreshing if stale
// This is the recommended function for most use cases
func GetCachedRegions(ctx context.Context, projectID string) []RegionInfo {
	cachedRegionsMu.RLock()
	if len(cachedRegions) > 0 && time.Since(cacheTime) < cacheTTL {
		result := make([]RegionInfo, len(cachedRegions))
		copy(result, cachedRegions)
		cachedRegionsMu.RUnlock()
		return result
	}
	cachedRegionsMu.RUnlock()

	// Fetch fresh
	svc := GetDefaultService()
	regions, _ := svc.GetRegions(ctx, projectID)

	// Update cache
	cachedRegionsMu.Lock()
	cachedRegions = regions
	cacheTime = time.Now()
	cachedRegionsMu.Unlock()

	return regions
}

// GetCachedRegionNames returns just region names from cache
func GetCachedRegionNames(ctx context.Context, projectID string) []string {
	regions := GetCachedRegions(ctx, projectID)
	names := make([]string, len(regions))
	for i, r := range regions {
		names[i] = r.Name
	}
	return names
}

// GetCachedZones returns all zones from cached regions
func GetCachedZones(ctx context.Context, projectID string) []string {
	regions := GetCachedRegions(ctx, projectID)
	var zones []string
	for _, r := range regions {
		zones = append(zones, r.Zones...)
	}
	return zones
}
