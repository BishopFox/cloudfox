// Package networkservice provides Azure Network service abstractions
//
// This service layer abstracts Azure Network API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package networkservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for network service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "networkservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// NetworkService provides methods for interacting with Azure Network resources
type NetworkService struct {
	session *azinternal.SafeSession
}

// New creates a new NetworkService instance
func New(session *azinternal.SafeSession) *NetworkService {
	return &NetworkService{
		session: session,
	}
}

// NewWithSession creates a new NetworkService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *NetworkService {
	return New(session)
}

// VNetInfo represents an Azure Virtual Network
type VNetInfo struct {
	Name          string
	ResourceGroup string
	Location      string
	AddressSpace  []string
	Subnets       []SubnetInfo
	DNSServers    []string
}

// SubnetInfo represents a subnet within a VNet
type SubnetInfo struct {
	Name          string
	AddressPrefix string
	NSGName       string
	RouteTable    string
}

// NSGInfo represents an Azure Network Security Group
type NSGInfo struct {
	Name          string
	ResourceGroup string
	Location      string
	Rules         []NSGRuleInfo
}

// NSGRuleInfo represents a rule in an NSG
type NSGRuleInfo struct {
	Name                   string
	Priority               int32
	Direction              string
	Access                 string
	Protocol               string
	SourcePortRange        string
	DestPortRange          string
	SourceAddressPrefix    string
	DestAddressPrefix      string
}

// NICInfo represents a Network Interface Card
type NICInfo struct {
	Name          string
	ResourceGroup string
	Location      string
	PrivateIP     string
	PublicIP      string
	VMName        string
	NSGName       string
}

// PublicIPInfo represents a public IP address
type PublicIPInfo struct {
	Name          string
	ResourceGroup string
	Location      string
	IPAddress     string
	Allocation    string
	FQDN          string
}

// LoadBalancerInfo represents an Azure Load Balancer
type LoadBalancerInfo struct {
	Name            string
	ResourceGroup   string
	Location        string
	SKU             string
	FrontendIPs     []string
	BackendPools    []string
}

// getARMCredential returns ARM credential from session
func (s *NetworkService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListVirtualNetworks returns all virtual networks in a subscription
func (s *NetworkService) ListVirtualNetworks(ctx context.Context, subID string) ([]*armnetwork.VirtualNetwork, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewVirtualNetworksClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VNet client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var vnets []*armnetwork.VirtualNetwork

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return vnets, fmt.Errorf("failed to list VNets: %w", err)
		}
		vnets = append(vnets, page.Value...)
	}

	return vnets, nil
}

// ListVirtualNetworksByResourceGroup returns all VNets in a resource group
func (s *NetworkService) ListVirtualNetworksByResourceGroup(ctx context.Context, subID, rgName string) ([]*armnetwork.VirtualNetwork, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewVirtualNetworksClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VNet client: %w", err)
	}

	pager := client.NewListPager(rgName, nil)
	var vnets []*armnetwork.VirtualNetwork

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return vnets, fmt.Errorf("failed to list VNets: %w", err)
		}
		vnets = append(vnets, page.Value...)
	}

	return vnets, nil
}

// ListNSGs returns all Network Security Groups in a subscription
func (s *NetworkService) ListNSGs(ctx context.Context, subID string) ([]*armnetwork.SecurityGroup, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewSecurityGroupsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NSG client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var nsgs []*armnetwork.SecurityGroup

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nsgs, fmt.Errorf("failed to list NSGs: %w", err)
		}
		nsgs = append(nsgs, page.Value...)
	}

	return nsgs, nil
}

// ListNSGsByResourceGroup returns all NSGs in a resource group
func (s *NetworkService) ListNSGsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armnetwork.SecurityGroup, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewSecurityGroupsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NSG client: %w", err)
	}

	pager := client.NewListPager(rgName, nil)
	var nsgs []*armnetwork.SecurityGroup

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nsgs, fmt.Errorf("failed to list NSGs: %w", err)
		}
		nsgs = append(nsgs, page.Value...)
	}

	return nsgs, nil
}

// ListNetworkInterfaces returns all NICs in a subscription
func (s *NetworkService) ListNetworkInterfaces(ctx context.Context, subID string) ([]*armnetwork.Interface, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewInterfacesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NIC client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var nics []*armnetwork.Interface

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nics, fmt.Errorf("failed to list NICs: %w", err)
		}
		nics = append(nics, page.Value...)
	}

	return nics, nil
}

// ListNetworkInterfacesByResourceGroup returns all NICs in a resource group
func (s *NetworkService) ListNetworkInterfacesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armnetwork.Interface, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewInterfacesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NIC client: %w", err)
	}

	pager := client.NewListPager(rgName, nil)
	var nics []*armnetwork.Interface

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nics, fmt.Errorf("failed to list NICs: %w", err)
		}
		nics = append(nics, page.Value...)
	}

	return nics, nil
}

// ListPublicIPAddresses returns all public IP addresses in a subscription
func (s *NetworkService) ListPublicIPAddresses(ctx context.Context, subID string) ([]*armnetwork.PublicIPAddress, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewPublicIPAddressesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create public IP client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var ips []*armnetwork.PublicIPAddress

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return ips, fmt.Errorf("failed to list public IPs: %w", err)
		}
		ips = append(ips, page.Value...)
	}

	return ips, nil
}

// ListLoadBalancers returns all load balancers in a subscription
func (s *NetworkService) ListLoadBalancers(ctx context.Context, subID string) ([]*armnetwork.LoadBalancer, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewLoadBalancersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancer client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var lbs []*armnetwork.LoadBalancer

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return lbs, fmt.Errorf("failed to list load balancers: %w", err)
		}
		lbs = append(lbs, page.Value...)
	}

	return lbs, nil
}

// ListRouteTables returns all route tables in a subscription
func (s *NetworkService) ListRouteTables(ctx context.Context, subID string) ([]*armnetwork.RouteTable, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewRouteTablesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create route table client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var tables []*armnetwork.RouteTable

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return tables, fmt.Errorf("failed to list route tables: %w", err)
		}
		tables = append(tables, page.Value...)
	}

	return tables, nil
}

// ListApplicationGateways returns all application gateways in a subscription
func (s *NetworkService) ListApplicationGateways(ctx context.Context, subID string) ([]*armnetwork.ApplicationGateway, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewApplicationGatewaysClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create app gateway client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var gateways []*armnetwork.ApplicationGateway

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return gateways, fmt.Errorf("failed to list application gateways: %w", err)
		}
		gateways = append(gateways, page.Value...)
	}

	return gateways, nil
}

// ListPrivateEndpoints returns all private endpoints in a subscription
func (s *NetworkService) ListPrivateEndpoints(ctx context.Context, subID string) ([]*armnetwork.PrivateEndpoint, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewPrivateEndpointsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create private endpoint client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var endpoints []*armnetwork.PrivateEndpoint

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return endpoints, fmt.Errorf("failed to list private endpoints: %w", err)
		}
		endpoints = append(endpoints, page.Value...)
	}

	return endpoints, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ============================================================================
// CACHED METHODS - Use these in command modules for better performance
// ============================================================================

// CachedListVirtualNetworks returns cached VNets for a subscription
func (s *NetworkService) CachedListVirtualNetworks(ctx context.Context, subID string) ([]*armnetwork.VirtualNetwork, error) {
	key := cacheKey("vnets", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.VirtualNetwork), nil
	}

	result, err := s.ListVirtualNetworks(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListVirtualNetworksByResourceGroup returns cached VNets for a resource group
func (s *NetworkService) CachedListVirtualNetworksByResourceGroup(ctx context.Context, subID, rgName string) ([]*armnetwork.VirtualNetwork, error) {
	key := cacheKey("vnets-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.VirtualNetwork), nil
	}

	result, err := s.ListVirtualNetworksByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListNSGs returns cached NSGs for a subscription
func (s *NetworkService) CachedListNSGs(ctx context.Context, subID string) ([]*armnetwork.SecurityGroup, error) {
	key := cacheKey("nsgs", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.SecurityGroup), nil
	}

	result, err := s.ListNSGs(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListNSGsByResourceGroup returns cached NSGs for a resource group
func (s *NetworkService) CachedListNSGsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armnetwork.SecurityGroup, error) {
	key := cacheKey("nsgs-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.SecurityGroup), nil
	}

	result, err := s.ListNSGsByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListNetworkInterfaces returns cached NICs for a subscription
func (s *NetworkService) CachedListNetworkInterfaces(ctx context.Context, subID string) ([]*armnetwork.Interface, error) {
	key := cacheKey("nics", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.Interface), nil
	}

	result, err := s.ListNetworkInterfaces(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListNetworkInterfacesByResourceGroup returns cached NICs for a resource group
func (s *NetworkService) CachedListNetworkInterfacesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armnetwork.Interface, error) {
	key := cacheKey("nics-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.Interface), nil
	}

	result, err := s.ListNetworkInterfacesByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPublicIPAddresses returns cached public IPs for a subscription
func (s *NetworkService) CachedListPublicIPAddresses(ctx context.Context, subID string) ([]*armnetwork.PublicIPAddress, error) {
	key := cacheKey("publicips", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.PublicIPAddress), nil
	}

	result, err := s.ListPublicIPAddresses(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListLoadBalancers returns cached load balancers for a subscription
func (s *NetworkService) CachedListLoadBalancers(ctx context.Context, subID string) ([]*armnetwork.LoadBalancer, error) {
	key := cacheKey("loadbalancers", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.LoadBalancer), nil
	}

	result, err := s.ListLoadBalancers(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListApplicationGateways returns cached application gateways for a subscription
func (s *NetworkService) CachedListApplicationGateways(ctx context.Context, subID string) ([]*armnetwork.ApplicationGateway, error) {
	key := cacheKey("appgateways", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.ApplicationGateway), nil
	}

	result, err := s.ListApplicationGateways(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPrivateEndpoints returns cached private endpoints for a subscription
func (s *NetworkService) CachedListPrivateEndpoints(ctx context.Context, subID string) ([]*armnetwork.PrivateEndpoint, error) {
	key := cacheKey("privateendpoints", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armnetwork.PrivateEndpoint), nil
	}

	result, err := s.ListPrivateEndpoints(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
