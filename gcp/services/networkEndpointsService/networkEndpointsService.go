package networkendpointsservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	compute "google.golang.org/api/compute/v1"
	servicenetworking "google.golang.org/api/servicenetworking/v1"
)

type NetworkEndpointsService struct {
	session *gcpinternal.SafeSession
}

func New() *NetworkEndpointsService {
	return &NetworkEndpointsService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *NetworkEndpointsService {
	return &NetworkEndpointsService{
		session: session,
	}
}

// getComputeService returns a Compute service client using cached session if available
func (s *NetworkEndpointsService) getComputeService(ctx context.Context) (*compute.Service, error) {
	if s.session != nil {
		return sdk.CachedGetComputeService(ctx, s.session)
	}
	return compute.NewService(ctx)
}

// getServiceNetworkingService returns a Service Networking service client using cached session if available
func (s *NetworkEndpointsService) getServiceNetworkingService(ctx context.Context) (*servicenetworking.APIService, error) {
	if s.session != nil {
		return sdk.CachedGetServiceNetworkingService(ctx, s.session)
	}
	return servicenetworking.NewService(ctx)
}

// PrivateServiceConnectEndpoint represents a PSC endpoint
type PrivateServiceConnectEndpoint struct {
	Name            string `json:"name"`
	ProjectID       string `json:"projectId"`
	Region          string `json:"region"`
	Network         string `json:"network"`
	Subnetwork      string `json:"subnetwork"`
	IPAddress       string `json:"ipAddress"`
	Target          string `json:"target"`         // Service attachment or API
	TargetType      string `json:"targetType"`     // google-apis, service-attachment
	ConnectionState string `json:"connectionState"`
}

// PrivateConnection represents a private service connection (e.g., for Cloud SQL)
type PrivateConnection struct {
	Name               string   `json:"name"`
	ProjectID          string   `json:"projectId"`
	Network            string   `json:"network"`
	Service            string   `json:"service"`
	ReservedRanges     []string `json:"reservedRanges"`
	PeeringName        string   `json:"peeringName"`
	AccessibleServices []string `json:"accessibleServices"`
}

// ServiceAttachmentIAMBinding represents an IAM binding for a service attachment
type ServiceAttachmentIAMBinding struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

// ServiceAttachment represents a PSC service attachment (producer side)
type ServiceAttachment struct {
	Name                 string                        `json:"name"`
	ProjectID            string                        `json:"projectId"`
	Region               string                        `json:"region"`
	TargetService        string                        `json:"targetService"`
	ConnectionPreference string                        `json:"connectionPreference"` // ACCEPT_AUTOMATIC, ACCEPT_MANUAL
	ConsumerAcceptLists  []string                      `json:"consumerAcceptLists"`
	ConsumerRejectLists  []string                      `json:"consumerRejectLists"`
	EnableProxyProtocol  bool                          `json:"enableProxyProtocol"`
	NatSubnets           []string                      `json:"natSubnets"`
	ConnectedEndpoints   int                           `json:"connectedEndpoints"`
	IAMBindings          []ServiceAttachmentIAMBinding `json:"iamBindings"`
}

// GetPrivateServiceConnectEndpoints retrieves PSC forwarding rules
func (s *NetworkEndpointsService) GetPrivateServiceConnectEndpoints(projectID string) ([]PrivateServiceConnectEndpoint, error) {
	ctx := context.Background()
	service, err := s.getComputeService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var endpoints []PrivateServiceConnectEndpoint

	// List forwarding rules across all regions
	req := service.ForwardingRules.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for region, scopedList := range page.Items {
			regionName := region
			if strings.HasPrefix(region, "regions/") {
				regionName = strings.TrimPrefix(region, "regions/")
			}

			for _, rule := range scopedList.ForwardingRules {
				// Check if this is a PSC endpoint
				if rule.Target == "" {
					continue
				}

				// PSC endpoints target service attachments or Google APIs
				isPSC := false
				targetType := ""

				if strings.Contains(rule.Target, "serviceAttachments") {
					isPSC = true
					targetType = "service-attachment"
				} else if strings.Contains(rule.Target, "all-apis") ||
				           strings.Contains(rule.Target, "vpc-sc") ||
				           rule.Target == "all-apis" {
					isPSC = true
					targetType = "google-apis"
				}

				if !isPSC {
					continue
				}

				endpoint := PrivateServiceConnectEndpoint{
					Name:       rule.Name,
					ProjectID:  projectID,
					Region:     regionName,
					Network:    extractName(rule.Network),
					Subnetwork: extractName(rule.Subnetwork),
					IPAddress:  rule.IPAddress,
					Target:     rule.Target,
					TargetType: targetType,
				}

				// Check connection state (for PSC endpoints to service attachments)
				if rule.PscConnectionStatus != "" {
					endpoint.ConnectionState = rule.PscConnectionStatus
				} else {
					endpoint.ConnectionState = "ACTIVE"
				}

				endpoints = append(endpoints, endpoint)
			}
		}
		return nil
	})

	return endpoints, err
}

// GetPrivateConnections retrieves private service connections
func (s *NetworkEndpointsService) GetPrivateConnections(projectID string) ([]PrivateConnection, error) {
	ctx := context.Background()
	service, err := s.getServiceNetworkingService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "servicenetworking.googleapis.com")
	}

	var connections []PrivateConnection

	// List connections for the project's networks
	computeService, err := s.getComputeService(ctx)
	if err != nil {
		return nil, err
	}

	// Get all networks
	networks, err := computeService.Networks.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	for _, network := range networks.Items {
		networkName := fmt.Sprintf("projects/%s/global/networks/%s", projectID, network.Name)

		// List connections for this network
		resp, err := service.Services.Connections.List("services/servicenetworking.googleapis.com").
			Network(networkName).Context(ctx).Do()
		if err != nil {
			continue // May not have permissions or no connections
		}

		for _, conn := range resp.Connections {
			connection := PrivateConnection{
				Name:           conn.Peering,
				ProjectID:      projectID,
				Network:        network.Name,
				Service:        conn.Service,
				ReservedRanges: conn.ReservedPeeringRanges,
				PeeringName:    conn.Peering,
			}

			// Determine accessible services based on the connection
			connection.AccessibleServices = s.determineAccessibleServices(conn.Service)

			connections = append(connections, connection)
		}
	}

	return connections, nil
}

// GetServiceAttachments retrieves PSC service attachments (producer side)
func (s *NetworkEndpointsService) GetServiceAttachments(projectID string) ([]ServiceAttachment, error) {
	ctx := context.Background()
	service, err := s.getComputeService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var attachments []ServiceAttachment

	req := service.ServiceAttachments.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.ServiceAttachmentAggregatedList) error {
		for region, scopedList := range page.Items {
			regionName := region
			if strings.HasPrefix(region, "regions/") {
				regionName = strings.TrimPrefix(region, "regions/")
			}

			for _, attachment := range scopedList.ServiceAttachments {
				sa := ServiceAttachment{
					Name:                 attachment.Name,
					ProjectID:            projectID,
					Region:               regionName,
					TargetService:        extractName(attachment.TargetService),
					ConnectionPreference: attachment.ConnectionPreference,
					EnableProxyProtocol:  attachment.EnableProxyProtocol,
				}

				// Extract NAT subnets
				for _, subnet := range attachment.NatSubnets {
					sa.NatSubnets = append(sa.NatSubnets, extractName(subnet))
				}

				// Count connected endpoints
				if attachment.ConnectedEndpoints != nil {
					sa.ConnectedEndpoints = len(attachment.ConnectedEndpoints)
				}

				// Extract consumer accept/reject lists
				for _, accept := range attachment.ConsumerAcceptLists {
					sa.ConsumerAcceptLists = append(sa.ConsumerAcceptLists, accept.ProjectIdOrNum)
				}
				for _, reject := range attachment.ConsumerRejectLists {
					sa.ConsumerRejectLists = append(sa.ConsumerRejectLists, reject)
				}

				// Get IAM bindings for the service attachment
				sa.IAMBindings = s.getServiceAttachmentIAMBindings(ctx, service, projectID, regionName, attachment.Name)

				attachments = append(attachments, sa)
			}
		}
		return nil
	})

	return attachments, err
}

// getServiceAttachmentIAMBindings retrieves IAM bindings for a service attachment
func (s *NetworkEndpointsService) getServiceAttachmentIAMBindings(ctx context.Context, service *compute.Service, projectID, region, attachmentName string) []ServiceAttachmentIAMBinding {
	policy, err := service.ServiceAttachments.GetIamPolicy(projectID, region, attachmentName).Context(ctx).Do()
	if err != nil {
		return nil
	}

	var bindings []ServiceAttachmentIAMBinding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		for _, member := range binding.Members {
			bindings = append(bindings, ServiceAttachmentIAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}
	return bindings
}

func (s *NetworkEndpointsService) determineAccessibleServices(service string) []string {
	// Map service names to what they provide access to
	serviceMap := map[string][]string{
		"servicenetworking.googleapis.com": {"Cloud SQL", "Memorystore", "Filestore", "Cloud Build"},
	}

	if services, ok := serviceMap[service]; ok {
		return services
	}
	return []string{service}
}

func extractName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}
