package bigtableservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	bigtableadmin "google.golang.org/api/bigtableadmin/v2"
)

type BigtableService struct {
	session *gcpinternal.SafeSession
}

func New() *BigtableService {
	return &BigtableService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *BigtableService {
	return &BigtableService{
		session: session,
	}
}

type BigtableInstanceInfo struct {
	Name         string        `json:"name"`
	FullName     string        `json:"fullName"`
	ProjectID    string        `json:"projectId"`
	DisplayName  string        `json:"displayName"`
	Type         string        `json:"type"`
	State        string        `json:"state"`
	Clusters     []ClusterInfo `json:"clusters"`
	IAMBindings  []IAMBinding  `json:"iamBindings"`
	PublicAccess bool          `json:"publicAccess"`
}

type BigtableTableInfo struct {
	Name         string       `json:"name"`
	FullName     string       `json:"fullName"`
	InstanceName string       `json:"instanceName"`
	ProjectID    string       `json:"projectId"`
	IAMBindings  []IAMBinding `json:"iamBindings"`
	PublicAccess bool         `json:"publicAccess"`
}

type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

type ClusterInfo struct {
	Name       string `json:"name"`
	Location   string `json:"location"`
	ServeNodes int64  `json:"serveNodes"`
	State      string `json:"state"`
}

type BigtableResult struct {
	Instances []BigtableInstanceInfo
	Tables    []BigtableTableInfo
}

// getService returns a Bigtable Admin service client using cached session if available
func (s *BigtableService) getService(ctx context.Context) (*bigtableadmin.Service, error) {
	if s.session != nil {
		return sdk.CachedGetBigtableAdminService(ctx, s.session)
	}
	return bigtableadmin.NewService(ctx)
}

func (s *BigtableService) ListInstances(projectID string) (*BigtableResult, error) {
	ctx := context.Background()
	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigtableadmin.googleapis.com")
	}

	result := &BigtableResult{
		Instances: []BigtableInstanceInfo{},
		Tables:    []BigtableTableInfo{},
	}

	parent := fmt.Sprintf("projects/%s", projectID)

	resp, err := service.Projects.Instances.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigtableadmin.googleapis.com")
	}

	for _, instance := range resp.Instances {
		info := BigtableInstanceInfo{
			Name:        extractName(instance.Name),
			FullName:    instance.Name,
			ProjectID:   projectID,
			DisplayName: instance.DisplayName,
			Type:        instance.Type,
			State:       instance.State,
		}

		// Get clusters
		clustersResp, clusterErr := service.Projects.Instances.Clusters.List(instance.Name).Context(ctx).Do()
		if clusterErr == nil && clustersResp != nil {
			for _, cluster := range clustersResp.Clusters {
				info.Clusters = append(info.Clusters, ClusterInfo{
					Name:       extractName(cluster.Name),
					Location:   cluster.Location,
					ServeNodes: cluster.ServeNodes,
					State:      cluster.State,
				})
			}
		}

		// Get tables and their IAM policies
		tablesResp, tableErr := service.Projects.Instances.Tables.List(instance.Name).Context(ctx).Do()
		if tableErr == nil && tablesResp != nil {
			for _, table := range tablesResp.Tables {
				tableInfo := BigtableTableInfo{
					Name:         extractName(table.Name),
					FullName:     table.Name,
					InstanceName: info.Name,
					ProjectID:    projectID,
				}

				// Get IAM policy for table
				tableIamResp, err := service.Projects.Instances.Tables.GetIamPolicy(table.Name, &bigtableadmin.GetIamPolicyRequest{}).Context(ctx).Do()
				if err == nil && tableIamResp != nil {
					for _, binding := range tableIamResp.Bindings {
						tableInfo.IAMBindings = append(tableInfo.IAMBindings, IAMBinding{
							Role:    binding.Role,
							Members: binding.Members,
						})
					}
					tableInfo.PublicAccess = checkPublicAccess(tableIamResp.Bindings)
				}

				result.Tables = append(result.Tables, tableInfo)
			}
		}

		// Get IAM policy for instance
		iamResp, err := service.Projects.Instances.GetIamPolicy(instance.Name, &bigtableadmin.GetIamPolicyRequest{}).Context(ctx).Do()
		if err == nil && iamResp != nil {
			for _, binding := range iamResp.Bindings {
				info.IAMBindings = append(info.IAMBindings, IAMBinding{
					Role:    binding.Role,
					Members: binding.Members,
				})
			}
			info.PublicAccess = checkPublicAccess(iamResp.Bindings)
		}

		result.Instances = append(result.Instances, info)
	}

	return result, nil
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// checkPublicAccess checks if any IAM binding grants access to allUsers or allAuthenticatedUsers
func checkPublicAccess(bindings []*bigtableadmin.Binding) bool {
	for _, binding := range bindings {
		for _, member := range binding.Members {
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				return true
			}
		}
	}
	return false
}
