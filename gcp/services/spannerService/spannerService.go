package spannerservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	spanner "google.golang.org/api/spanner/v1"
)

type SpannerService struct {
	session *gcpinternal.SafeSession
}

func New() *SpannerService {
	return &SpannerService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *SpannerService {
	return &SpannerService{
		session: session,
	}
}

// IAMBinding represents a single IAM binding (one role + one member)
type IAMBinding struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

type SpannerInstanceInfo struct {
	Name        string       `json:"name"`
	FullName    string       `json:"fullName"`
	ProjectID   string       `json:"projectId"`
	DisplayName string       `json:"displayName"`
	Config      string       `json:"config"`
	NodeCount   int64        `json:"nodeCount"`
	State       string       `json:"state"`
	IAMBindings []IAMBinding `json:"iamBindings"`
}

type SpannerDatabaseInfo struct {
	Name           string       `json:"name"`
	FullName       string       `json:"fullName"`
	ProjectID      string       `json:"projectId"`
	InstanceName   string       `json:"instanceName"`
	State          string       `json:"state"`
	EncryptionType string       `json:"encryptionType"`
	KmsKeyName     string       `json:"kmsKeyName"`
	IAMBindings    []IAMBinding `json:"iamBindings"`
}

type SpannerResult struct {
	Instances []SpannerInstanceInfo
	Databases []SpannerDatabaseInfo
}

// getService returns a Spanner service client using cached session if available
func (s *SpannerService) getService(ctx context.Context) (*spanner.Service, error) {
	if s.session != nil {
		return sdk.CachedGetSpannerService(ctx, s.session)
	}
	return spanner.NewService(ctx)
}

// ListInstancesAndDatabases retrieves all Spanner instances and databases with IAM bindings
func (s *SpannerService) ListInstancesAndDatabases(projectID string) (*SpannerResult, error) {
	ctx := context.Background()
	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "spanner.googleapis.com")
	}

	result := &SpannerResult{
		Instances: []SpannerInstanceInfo{},
		Databases: []SpannerDatabaseInfo{},
	}

	parent := fmt.Sprintf("projects/%s", projectID)

	req := service.Projects.Instances.List(parent)
	err = req.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			info := SpannerInstanceInfo{
				Name:        extractName(instance.Name),
				FullName:    instance.Name,
				ProjectID:   projectID,
				DisplayName: instance.DisplayName,
				Config:      extractName(instance.Config),
				NodeCount:   instance.NodeCount,
				State:       instance.State,
			}

			// Get IAM bindings for this instance
			info.IAMBindings = s.getInstanceIAMBindings(service, ctx, instance.Name)

			result.Instances = append(result.Instances, info)

			// Get databases for this instance
			databases := s.listDatabases(service, ctx, instance.Name, projectID)
			result.Databases = append(result.Databases, databases...)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "spanner.googleapis.com")
	}

	return result, nil
}

// getInstanceIAMBindings retrieves IAM bindings for an instance
func (s *SpannerService) getInstanceIAMBindings(service *spanner.Service, ctx context.Context, instanceName string) []IAMBinding {
	var bindings []IAMBinding

	policy, err := service.Projects.Instances.GetIamPolicy(instanceName, &spanner.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return bindings
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}

	return bindings
}

// listDatabases retrieves all databases for an instance with their IAM bindings
func (s *SpannerService) listDatabases(service *spanner.Service, ctx context.Context, instanceName string, projectID string) []SpannerDatabaseInfo {
	var databases []SpannerDatabaseInfo

	req := service.Projects.Instances.Databases.List(instanceName)
	err := req.Pages(ctx, func(page *spanner.ListDatabasesResponse) error {
		for _, db := range page.Databases {
			dbInfo := SpannerDatabaseInfo{
				Name:         extractName(db.Name),
				FullName:     db.Name,
				ProjectID:    projectID,
				InstanceName: extractName(instanceName),
				State:        db.State,
			}

			// Determine encryption type
			if db.EncryptionConfig != nil && db.EncryptionConfig.KmsKeyName != "" {
				dbInfo.EncryptionType = "CMEK"
				dbInfo.KmsKeyName = db.EncryptionConfig.KmsKeyName
			} else {
				dbInfo.EncryptionType = "Google-managed"
			}

			// Get IAM bindings for this database
			dbInfo.IAMBindings = s.getDatabaseIAMBindings(service, ctx, db.Name)

			databases = append(databases, dbInfo)
		}
		return nil
	})
	if err != nil {
		// Log but don't fail - return whatever we collected
		return databases
	}

	return databases
}

// getDatabaseIAMBindings retrieves IAM bindings for a database
func (s *SpannerService) getDatabaseIAMBindings(service *spanner.Service, ctx context.Context, databaseName string) []IAMBinding {
	var bindings []IAMBinding

	policy, err := service.Projects.Instances.Databases.GetIamPolicy(databaseName, &spanner.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return bindings
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}

	return bindings
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
