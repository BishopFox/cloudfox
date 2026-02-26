// Package dnsservice provides Azure DNS service abstractions
//
// This service layer abstracts Azure DNS API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package dnsservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for DNS service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "dnsservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// DNSService provides methods for interacting with Azure DNS
type DNSService struct {
	session *azinternal.SafeSession
}

// New creates a new DNSService instance
func New(session *azinternal.SafeSession) *DNSService {
	return &DNSService{
		session: session,
	}
}

// NewWithSession creates a new DNSService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *DNSService {
	return New(session)
}

// ZoneInfo represents a DNS zone
type ZoneInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	ZoneType          string
	NumberOfRecordSets int64
	NameServers       []string
}

// RecordSetInfo represents a DNS record set
type RecordSetInfo struct {
	Name       string
	ZoneName   string
	Type       string
	TTL        int64
	Values     []string
}

// PrivateZoneInfo represents a private DNS zone
type PrivateZoneInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	NumberOfRecordSets int64
	VNetLinks         int64
}

// getARMCredential returns ARM credential from session
func (s *DNSService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListZones returns all public DNS zones in a subscription
func (s *DNSService) ListZones(ctx context.Context, subID string) ([]*armdns.Zone, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armdns.NewZonesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS zones client: %w", err)
	}

	pager := client.NewListPager(nil)
	var zones []*armdns.Zone

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return zones, fmt.Errorf("failed to list DNS zones: %w", err)
		}
		zones = append(zones, page.Value...)
	}

	return zones, nil
}

// ListZonesByResourceGroup returns all DNS zones in a resource group
func (s *DNSService) ListZonesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armdns.Zone, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armdns.NewZonesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS zones client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var zones []*armdns.Zone

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return zones, fmt.Errorf("failed to list DNS zones: %w", err)
		}
		zones = append(zones, page.Value...)
	}

	return zones, nil
}

// ListRecordSets returns all record sets in a DNS zone
func (s *DNSService) ListRecordSets(ctx context.Context, subID, rgName, zoneName string) ([]*armdns.RecordSet, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armdns.NewRecordSetsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create record sets client: %w", err)
	}

	pager := client.NewListByDNSZonePager(rgName, zoneName, nil)
	var recordSets []*armdns.RecordSet

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return recordSets, fmt.Errorf("failed to list record sets: %w", err)
		}
		recordSets = append(recordSets, page.Value...)
	}

	return recordSets, nil
}

// ListPrivateZones returns all private DNS zones in a subscription
func (s *DNSService) ListPrivateZones(ctx context.Context, subID string) ([]*armprivatedns.PrivateZone, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armprivatedns.NewPrivateZonesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create private DNS zones client: %w", err)
	}

	pager := client.NewListPager(nil)
	var zones []*armprivatedns.PrivateZone

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return zones, fmt.Errorf("failed to list private DNS zones: %w", err)
		}
		zones = append(zones, page.Value...)
	}

	return zones, nil
}

// ListPrivateZonesByResourceGroup returns all private DNS zones in a resource group
func (s *DNSService) ListPrivateZonesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armprivatedns.PrivateZone, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armprivatedns.NewPrivateZonesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create private DNS zones client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var zones []*armprivatedns.PrivateZone

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return zones, fmt.Errorf("failed to list private DNS zones: %w", err)
		}
		zones = append(zones, page.Value...)
	}

	return zones, nil
}

// ListVirtualNetworkLinks returns all VNet links for a private DNS zone
func (s *DNSService) ListVirtualNetworkLinks(ctx context.Context, subID, rgName, zoneName string) ([]*armprivatedns.VirtualNetworkLink, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armprivatedns.NewVirtualNetworkLinksClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VNet links client: %w", err)
	}

	pager := client.NewListPager(rgName, zoneName, nil)
	var links []*armprivatedns.VirtualNetworkLink

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return links, fmt.Errorf("failed to list VNet links: %w", err)
		}
		links = append(links, page.Value...)
	}

	return links, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// =============================================================================
// Cached Methods
// =============================================================================

// CachedListZones returns all public DNS zones with caching
func (s *DNSService) CachedListZones(ctx context.Context, subID string) ([]*armdns.Zone, error) {
	key := cacheKey("zones", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armdns.Zone), nil
	}
	result, err := s.ListZones(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPrivateZones returns all private DNS zones with caching
func (s *DNSService) CachedListPrivateZones(ctx context.Context, subID string) ([]*armprivatedns.PrivateZone, error) {
	key := cacheKey("privatezones", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armprivatedns.PrivateZone), nil
	}
	result, err := s.ListPrivateZones(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListRecordSets returns all record sets in a DNS zone with caching
func (s *DNSService) CachedListRecordSets(ctx context.Context, subID, rgName, zoneName string) ([]*armdns.RecordSet, error) {
	key := cacheKey("recordsets", subID, rgName, zoneName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armdns.RecordSet), nil
	}
	result, err := s.ListRecordSets(ctx, subID, rgName, zoneName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
