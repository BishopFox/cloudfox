package bigtableenumservice

import (
	"context"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/gcp/shared"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	bigtableadmin "google.golang.org/api/bigtableadmin/v2"
)

type BigtableEnumService struct {
	session *gcpinternal.SafeSession
}

func New() *BigtableEnumService {
	return &BigtableEnumService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *BigtableEnumService {
	return &BigtableEnumService{session: session}
}

// SensitiveBTResource represents a Bigtable resource flagged as potentially sensitive.
type SensitiveBTResource struct {
	ProjectID    string `json:"projectId"`
	Instance     string `json:"instance"`
	Table        string `json:"table"`
	ColumnFamily string `json:"columnFamily"`
	Category     string `json:"category"`
	RiskLevel    string `json:"riskLevel"`
	Description  string `json:"description"`
}

// getBigtableAdminService returns a Bigtable Admin service client.
func (s *BigtableEnumService) getBigtableAdminService(ctx context.Context) (*bigtableadmin.Service, error) {
	return bigtableadmin.NewService(ctx)
}

// EnumerateSensitiveResources scans Bigtable metadata for sensitive resource names.
func (s *BigtableEnumService) EnumerateSensitiveResources(projectID string) ([]SensitiveBTResource, error) {
	ctx := context.Background()

	service, err := s.getBigtableAdminService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigtableadmin.googleapis.com")
	}

	namePatterns := shared.GetNamePatterns()
	var resources []SensitiveBTResource

	// List instances
	parent := fmt.Sprintf("projects/%s", projectID)
	instancesResp, err := service.Projects.Instances.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigtableadmin.googleapis.com")
	}

	for _, instance := range instancesResp.Instances {
		instanceName := extractName(instance.Name)

		// Check instance name
		if match := shared.MatchResourceName(instanceName, namePatterns); match != nil {
			resources = append(resources, SensitiveBTResource{
				ProjectID:   projectID,
				Instance:    instanceName,
				Category:    match.Category,
				RiskLevel:   match.RiskLevel,
				Description: fmt.Sprintf("Instance name: %s", match.Description),
			})
		}

		// List tables
		tablesResp, err := service.Projects.Instances.Tables.List(instance.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, table := range tablesResp.Tables {
			tableName := extractName(table.Name)

			// Check table name
			if match := shared.MatchResourceName(tableName, namePatterns); match != nil {
				resources = append(resources, SensitiveBTResource{
					ProjectID:   projectID,
					Instance:    instanceName,
					Table:       tableName,
					Category:    match.Category,
					RiskLevel:   match.RiskLevel,
					Description: fmt.Sprintf("Table name: %s", match.Description),
				})
			}

			// Check column family names
			for cfName := range table.ColumnFamilies {
				if match := shared.MatchResourceName(cfName, namePatterns); match != nil {
					resources = append(resources, SensitiveBTResource{
						ProjectID:    projectID,
						Instance:     instanceName,
						Table:        tableName,
						ColumnFamily: cfName,
						Category:     match.Category,
						RiskLevel:    match.RiskLevel,
						Description:  fmt.Sprintf("Column family name: %s", match.Description),
					})
				}
			}
		}
	}

	return resources, nil
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
