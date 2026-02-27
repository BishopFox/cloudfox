package bigqueryenumservice

import (
	"context"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/gcp/shared"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	bigquery "google.golang.org/api/bigquery/v2"
)

type BigQueryEnumService struct {
	session *gcpinternal.SafeSession
}

func New() *BigQueryEnumService {
	return &BigQueryEnumService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *BigQueryEnumService {
	return &BigQueryEnumService{session: session}
}

// SensitiveBQResource represents a BigQuery resource flagged as potentially sensitive.
type SensitiveBQResource struct {
	ProjectID   string `json:"projectId"`
	Dataset     string `json:"dataset"`
	Table       string `json:"table"`
	Column      string `json:"column"`
	MatchType   string `json:"matchType"` // "name" or "content"
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// getBigQueryService returns a BigQuery service client.
func (s *BigQueryEnumService) getBigQueryService(ctx context.Context) (*bigquery.Service, error) {
	return bigquery.NewService(ctx)
}

// EnumerateSensitiveResources scans BigQuery metadata for sensitive resource names.
func (s *BigQueryEnumService) EnumerateSensitiveResources(projectID string, maxTables int, sampleData bool, maxRows int) ([]SensitiveBQResource, error) {
	ctx := context.Background()

	service, err := s.getBigQueryService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
	}

	namePatterns := shared.GetNamePatterns()
	contentPatterns := shared.GetContentPatterns()

	var resources []SensitiveBQResource
	tableCount := 0

	// List datasets
	datasetsResp, err := service.Datasets.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
	}

	for _, ds := range datasetsResp.Datasets {
		datasetID := ds.DatasetReference.DatasetId

		// Check dataset name
		if match := shared.MatchResourceName(datasetID, namePatterns); match != nil {
			resources = append(resources, SensitiveBQResource{
				ProjectID:   projectID,
				Dataset:     datasetID,
				MatchType:   "name",
				Category:    match.Category,
				RiskLevel:   match.RiskLevel,
				Description: fmt.Sprintf("Dataset name: %s", match.Description),
			})
		}

		// List tables in dataset
		tablesResp, err := service.Tables.List(projectID, datasetID).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, tbl := range tablesResp.Tables {
			if maxTables > 0 && tableCount >= maxTables {
				break
			}
			tableCount++

			tableID := tbl.TableReference.TableId

			// Check table name
			if match := shared.MatchResourceName(tableID, namePatterns); match != nil {
				resources = append(resources, SensitiveBQResource{
					ProjectID:   projectID,
					Dataset:     datasetID,
					Table:       tableID,
					MatchType:   "name",
					Category:    match.Category,
					RiskLevel:   match.RiskLevel,
					Description: fmt.Sprintf("Table name: %s", match.Description),
				})
			}

			// Get table schema to check column names
			tableDetail, err := service.Tables.Get(projectID, datasetID, tableID).Context(ctx).Do()
			if err != nil {
				continue
			}

			if tableDetail.Schema != nil {
				for _, field := range tableDetail.Schema.Fields {
					if match := shared.MatchResourceName(field.Name, namePatterns); match != nil {
						resources = append(resources, SensitiveBQResource{
							ProjectID:   projectID,
							Dataset:     datasetID,
							Table:       tableID,
							Column:      field.Name,
							MatchType:   "name",
							Category:    match.Category,
							RiskLevel:   match.RiskLevel,
							Description: fmt.Sprintf("Column name: %s", match.Description),
						})
					}
				}
			}

			// Phase 2: Optional data sampling
			if sampleData && wasTableFlagged(resources, projectID, datasetID, tableID) {
				sampleResults := s.sampleTableData(ctx, service, projectID, datasetID, tableID, maxRows, contentPatterns)
				resources = append(resources, sampleResults...)
			}
		}

		if maxTables > 0 && tableCount >= maxTables {
			break
		}
	}

	return resources, nil
}

// wasTableFlagged checks if a table was already flagged by name matching.
func wasTableFlagged(resources []SensitiveBQResource, projectID, dataset, table string) bool {
	for _, r := range resources {
		if r.ProjectID == projectID && r.Dataset == dataset && r.Table == table {
			return true
		}
	}
	return false
}

// sampleTableData runs a SELECT query on a flagged table and scans results.
func (s *BigQueryEnumService) sampleTableData(ctx context.Context, service *bigquery.Service, projectID, datasetID, tableID string, maxRows int, patterns []shared.ContentPattern) []SensitiveBQResource {
	var results []SensitiveBQResource

	query := fmt.Sprintf("SELECT * FROM `%s.%s.%s` LIMIT %d", projectID, datasetID, tableID, maxRows)

	useLegacySQL := false
	job := &bigquery.Job{
		Configuration: &bigquery.JobConfiguration{
			Query: &bigquery.JobConfigurationQuery{
				Query:           query,
				UseLegacySql:    &useLegacySQL,
				ForceSendFields: []string{"UseLegacySql"},
			},
		},
	}

	insertedJob, err := service.Jobs.Insert(projectID, job).Context(ctx).Do()
	if err != nil {
		return results
	}

	// Wait for query to complete (simple polling)
	for {
		status, err := service.Jobs.Get(projectID, insertedJob.JobReference.JobId).Context(ctx).Do()
		if err != nil {
			return results
		}
		if status.Status.State == "DONE" {
			if status.Status.ErrorResult != nil {
				return results
			}
			break
		}
	}

	// Get results
	queryResults, err := service.Jobs.GetQueryResults(projectID, insertedJob.JobReference.JobId).Context(ctx).Do()
	if err != nil {
		return results
	}

	// Scan each row
	for _, row := range queryResults.Rows {
		for _, cell := range row.F {
			cellStr := fmt.Sprintf("%v", cell.V)
			if cellStr == "" || cellStr == "<nil>" {
				continue
			}
			matches := shared.MatchContent(cellStr, patterns)
			for _, match := range matches {
				results = append(results, SensitiveBQResource{
					ProjectID:   projectID,
					Dataset:     datasetID,
					Table:       tableID,
					MatchType:   "content",
					Category:    match.Category,
					RiskLevel:   match.RiskLevel,
					Description: fmt.Sprintf("Data content: %s", match.Description),
				})
				break // One match per cell is sufficient
			}
		}
	}

	// Deduplicate content matches per table
	return deduplicateByCategory(results)
}

func deduplicateByCategory(resources []SensitiveBQResource) []SensitiveBQResource {
	seen := make(map[string]bool)
	var result []SensitiveBQResource
	for _, r := range resources {
		key := strings.Join([]string{r.ProjectID, r.Dataset, r.Table, r.Category, r.MatchType}, "|")
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}
	return result
}
