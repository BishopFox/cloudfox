package beyondcorpservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	beyondcorp "google.golang.org/api/beyondcorp/v1"
)

type BeyondCorpService struct {
	session *gcpinternal.SafeSession
}

func New() *BeyondCorpService {
	return &BeyondCorpService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *BeyondCorpService {
	return &BeyondCorpService{session: session}
}

// getService returns a BeyondCorp service client using cached session if available
func (s *BeyondCorpService) getService(ctx context.Context) (*beyondcorp.Service, error) {
	if s.session != nil {
		return sdk.CachedGetBeyondCorpService(ctx, s.session)
	}
	return beyondcorp.NewService(ctx)
}

// IAMBinding represents an IAM binding
type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// AppConnectorInfo represents a BeyondCorp app connector
type AppConnectorInfo struct {
	Name          string       `json:"name"`
	FullName      string       `json:"fullName"`
	ProjectID     string       `json:"projectId"`
	Location      string       `json:"location"`
	DisplayName   string       `json:"displayName"`
	State         string       `json:"state"`
	CreateTime    string       `json:"createTime"`
	UpdateTime    string       `json:"updateTime"`
	PrincipalInfo string       `json:"principalInfo"`
	ResourceInfo  string       `json:"resourceInfo"`
	IAMBindings   []IAMBinding `json:"iamBindings"`
	PublicAccess  bool         `json:"publicAccess"`
}

// AppConnectionInfo represents a BeyondCorp app connection
type AppConnectionInfo struct {
	Name                string       `json:"name"`
	FullName            string       `json:"fullName"`
	ProjectID           string       `json:"projectId"`
	Location            string       `json:"location"`
	DisplayName         string       `json:"displayName"`
	State               string       `json:"state"`
	Type                string       `json:"type"`
	ApplicationEndpoint string       `json:"applicationEndpoint"`
	Connectors          []string     `json:"connectors"`
	Gateway             string       `json:"gateway"`
	CreateTime          string       `json:"createTime"`
	UpdateTime          string       `json:"updateTime"`
	IAMBindings         []IAMBinding `json:"iamBindings"`
	PublicAccess        bool         `json:"publicAccess"`
}

// ListAppConnectors retrieves all BeyondCorp app connectors
func (s *BeyondCorpService) ListAppConnectors(projectID string) ([]AppConnectorInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "beyondcorp.googleapis.com")
	}

	var connectors []AppConnectorInfo

	// List across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := service.Projects.Locations.AppConnectors.List(parent)
	err = req.Pages(ctx, func(page *beyondcorp.GoogleCloudBeyondcorpAppconnectorsV1ListAppConnectorsResponse) error {
		for _, connector := range page.AppConnectors {
			info := s.parseAppConnector(connector, projectID)

			// Get IAM policy for this connector
			iamPolicy, iamErr := service.Projects.Locations.AppConnectors.GetIamPolicy(connector.Name).Context(ctx).Do()
			if iamErr == nil && iamPolicy != nil {
				for _, binding := range iamPolicy.Bindings {
					info.IAMBindings = append(info.IAMBindings, IAMBinding{
						Role:    binding.Role,
						Members: binding.Members,
					})
					// Check for public access
					for _, member := range binding.Members {
						if member == "allUsers" || member == "allAuthenticatedUsers" {
							info.PublicAccess = true
						}
					}
				}
			}

			connectors = append(connectors, info)
		}
		return nil
	})
	if err != nil {
		return connectors, gcpinternal.ParseGCPError(err, "beyondcorp.googleapis.com")
	}

	return connectors, nil
}

// ListAppConnections retrieves all BeyondCorp app connections
func (s *BeyondCorpService) ListAppConnections(projectID string) ([]AppConnectionInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "beyondcorp.googleapis.com")
	}

	var connections []AppConnectionInfo

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := service.Projects.Locations.AppConnections.List(parent)
	err = req.Pages(ctx, func(page *beyondcorp.GoogleCloudBeyondcorpAppconnectionsV1ListAppConnectionsResponse) error {
		for _, conn := range page.AppConnections {
			info := s.parseAppConnection(conn, projectID)

			// Get IAM policy for this connection
			iamPolicy, iamErr := service.Projects.Locations.AppConnections.GetIamPolicy(conn.Name).Context(ctx).Do()
			if iamErr == nil && iamPolicy != nil {
				for _, binding := range iamPolicy.Bindings {
					info.IAMBindings = append(info.IAMBindings, IAMBinding{
						Role:    binding.Role,
						Members: binding.Members,
					})
					// Check for public access
					for _, member := range binding.Members {
						if member == "allUsers" || member == "allAuthenticatedUsers" {
							info.PublicAccess = true
						}
					}
				}
			}

			connections = append(connections, info)
		}
		return nil
	})
	if err != nil {
		return connections, gcpinternal.ParseGCPError(err, "beyondcorp.googleapis.com")
	}

	return connections, nil
}

func (s *BeyondCorpService) parseAppConnector(connector *beyondcorp.GoogleCloudBeyondcorpAppconnectorsV1AppConnector, projectID string) AppConnectorInfo {
	info := AppConnectorInfo{
		Name:        extractName(connector.Name),
		FullName:    connector.Name,
		ProjectID:   projectID,
		Location:    extractLocation(connector.Name),
		DisplayName: connector.DisplayName,
		State:       connector.State,
		CreateTime:  connector.CreateTime,
		UpdateTime:  connector.UpdateTime,
	}

	if connector.PrincipalInfo != nil && connector.PrincipalInfo.ServiceAccount != nil {
		info.PrincipalInfo = connector.PrincipalInfo.ServiceAccount.Email
	}

	if connector.ResourceInfo != nil {
		info.ResourceInfo = connector.ResourceInfo.Id
	}

	return info
}

func (s *BeyondCorpService) parseAppConnection(conn *beyondcorp.GoogleCloudBeyondcorpAppconnectionsV1AppConnection, projectID string) AppConnectionInfo {
	info := AppConnectionInfo{
		Name:        extractName(conn.Name),
		FullName:    conn.Name,
		ProjectID:   projectID,
		Location:    extractLocation(conn.Name),
		DisplayName: conn.DisplayName,
		State:       conn.State,
		Type:        conn.Type,
		CreateTime:  conn.CreateTime,
		UpdateTime:  conn.UpdateTime,
	}

	if conn.ApplicationEndpoint != nil {
		info.ApplicationEndpoint = fmt.Sprintf("%s:%d", conn.ApplicationEndpoint.Host, conn.ApplicationEndpoint.Port)
	}

	for _, connector := range conn.Connectors {
		info.Connectors = append(info.Connectors, extractName(connector))
	}

	if conn.Gateway != nil {
		info.Gateway = extractName(conn.Gateway.AppGateway)
	}

	return info
}

func extractName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}

func extractLocation(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
