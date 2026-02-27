package vpcservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	compute "google.golang.org/api/compute/v1"
)

type VPCService struct {
	session *gcpinternal.SafeSession
}

func New() *VPCService {
	return &VPCService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *VPCService {
	return &VPCService{session: session}
}

// getService returns a Compute service client using cached session if available
func (s *VPCService) getService(ctx context.Context) (*compute.Service, error) {
	if s.session != nil {
		return sdk.CachedGetComputeService(ctx, s.session)
	}
	return compute.NewService(ctx)
}

// VPCNetworkInfo represents a VPC network
type VPCNetworkInfo struct {
	Name                  string   `json:"name"`
	ProjectID             string   `json:"projectId"`
	Description           string   `json:"description"`
	AutoCreateSubnetworks bool     `json:"autoCreateSubnetworks"`
	RoutingMode           string   `json:"routingMode"` // REGIONAL or GLOBAL
	MTU                   int64    `json:"mtu"`
	Subnetworks           []string `json:"subnetworks"`
	Peerings              []string `json:"peerings"`
	FirewallPolicyCount   int      `json:"firewallPolicyCount"`
}

// SubnetInfo represents a subnetwork
type SubnetInfo struct {
	Name                  string   `json:"name"`
	ProjectID             string   `json:"projectId"`
	Network               string   `json:"network"`
	Region                string   `json:"region"`
	IPCidrRange           string   `json:"ipCidrRange"`
	GatewayAddress        string   `json:"gatewayAddress"`
	PrivateIPGoogleAccess bool     `json:"privateIpGoogleAccess"`
	Purpose               string   `json:"purpose"`
	EnableFlowLogs        bool     `json:"enableFlowLogs"`
	SecondaryIPRanges     []string `json:"secondaryIpRanges"`
}

// VPCPeeringInfo represents a VPC peering connection
type VPCPeeringInfo struct {
	Name                 string `json:"name"`
	ProjectID            string `json:"projectId"`
	Network              string `json:"network"`
	PeerNetwork          string `json:"peerNetwork"`
	PeerProjectID        string `json:"peerProjectId"`
	State                string `json:"state"`
	ExportCustomRoutes   bool   `json:"exportCustomRoutes"`
	ImportCustomRoutes   bool   `json:"importCustomRoutes"`
	ExchangeSubnetRoutes bool   `json:"exchangeSubnetRoutes"`
}

// RouteInfo represents a route
type RouteInfo struct {
	Name        string   `json:"name"`
	ProjectID   string   `json:"projectId"`
	Network     string   `json:"network"`
	DestRange   string   `json:"destRange"`
	NextHopType string   `json:"nextHopType"`
	NextHop     string   `json:"nextHop"`
	Priority    int64    `json:"priority"`
	Tags        []string `json:"tags"`
}

// ListVPCNetworks retrieves all VPC networks
func (s *VPCService) ListVPCNetworks(projectID string) ([]VPCNetworkInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var networks []VPCNetworkInfo

	resp, err := service.Networks.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	for _, network := range resp.Items {
		info := s.parseNetwork(network, projectID)
		networks = append(networks, info)
	}

	return networks, nil
}

// ListSubnets retrieves all subnets
func (s *VPCService) ListSubnets(projectID string) ([]SubnetInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var subnets []SubnetInfo

	req := service.Subnetworks.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, subnet := range scopedList.Subnetworks {
				info := s.parseSubnet(subnet, projectID)
				subnets = append(subnets, info)
			}
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	return subnets, nil
}

// ListVPCPeerings retrieves all VPC peering connections
func (s *VPCService) ListVPCPeerings(projectID string) ([]VPCPeeringInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var peerings []VPCPeeringInfo

	networks, err := service.Networks.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	for _, network := range networks.Items {
		for _, peering := range network.Peerings {
			// Extract peer project ID from the full network path
			peerProjectID := extractProjectFromNetwork(peering.Network)

			info := VPCPeeringInfo{
				Name:                 peering.Name,
				ProjectID:            projectID,
				Network:              network.Name,
				PeerNetwork:          extractName(peering.Network),
				PeerProjectID:        peerProjectID,
				State:                peering.State,
				ExportCustomRoutes:   peering.ExportCustomRoutes,
				ImportCustomRoutes:   peering.ImportCustomRoutes,
				ExchangeSubnetRoutes: peering.ExchangeSubnetRoutes,
			}
			peerings = append(peerings, info)
		}
	}

	return peerings, nil
}

// ListRoutes retrieves all routes
func (s *VPCService) ListRoutes(projectID string) ([]RouteInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var routes []RouteInfo

	resp, err := service.Routes.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	for _, route := range resp.Items {
		info := s.parseRoute(route, projectID)
		routes = append(routes, info)
	}

	return routes, nil
}

func (s *VPCService) parseNetwork(network *compute.Network, projectID string) VPCNetworkInfo {
	info := VPCNetworkInfo{
		Name:                  network.Name,
		ProjectID:             projectID,
		Description:           network.Description,
		AutoCreateSubnetworks: network.AutoCreateSubnetworks,
		RoutingMode:           network.RoutingConfig.RoutingMode,
		MTU:                   network.Mtu,
	}

	for _, subnet := range network.Subnetworks {
		info.Subnetworks = append(info.Subnetworks, extractName(subnet))
	}

	for _, peering := range network.Peerings {
		info.Peerings = append(info.Peerings, peering.Name)
	}

	return info
}

func (s *VPCService) parseSubnet(subnet *compute.Subnetwork, projectID string) SubnetInfo {
	info := SubnetInfo{
		Name:                  subnet.Name,
		ProjectID:             projectID,
		Network:               extractName(subnet.Network),
		Region:                extractRegion(subnet.Region),
		IPCidrRange:           subnet.IpCidrRange,
		GatewayAddress:        subnet.GatewayAddress,
		PrivateIPGoogleAccess: subnet.PrivateIpGoogleAccess,
		Purpose:               subnet.Purpose,
	}

	if subnet.LogConfig != nil {
		info.EnableFlowLogs = subnet.LogConfig.Enable
	}

	for _, secondary := range subnet.SecondaryIpRanges {
		info.SecondaryIPRanges = append(info.SecondaryIPRanges, fmt.Sprintf("%s:%s", secondary.RangeName, secondary.IpCidrRange))
	}

	return info
}

func (s *VPCService) parseRoute(route *compute.Route, projectID string) RouteInfo {
	info := RouteInfo{
		Name:      route.Name,
		ProjectID: projectID,
		Network:   extractName(route.Network),
		DestRange: route.DestRange,
		Priority:  route.Priority,
		Tags:      route.Tags,
	}

	// Determine next hop type
	if route.NextHopGateway != "" {
		info.NextHopType = "gateway"
		info.NextHop = extractName(route.NextHopGateway)
	} else if route.NextHopInstance != "" {
		info.NextHopType = "instance"
		info.NextHop = extractName(route.NextHopInstance)
	} else if route.NextHopIp != "" {
		info.NextHopType = "ip"
		info.NextHop = route.NextHopIp
	} else if route.NextHopNetwork != "" {
		info.NextHopType = "network"
		info.NextHop = extractName(route.NextHopNetwork)
	} else if route.NextHopPeering != "" {
		info.NextHopType = "peering"
		info.NextHop = route.NextHopPeering
	} else if route.NextHopIlb != "" {
		info.NextHopType = "ilb"
		info.NextHop = extractName(route.NextHopIlb)
	} else if route.NextHopVpnTunnel != "" {
		info.NextHopType = "vpn_tunnel"
		info.NextHop = extractName(route.NextHopVpnTunnel)
	}

	return info
}

func extractProjectFromNetwork(networkPath string) string {
	// Format: https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}
	// or: projects/{project}/global/networks/{network}
	parts := strings.Split(networkPath, "/")
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func extractName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}

func extractRegion(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	for i, part := range parts {
		if part == "regions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return fullPath
}
