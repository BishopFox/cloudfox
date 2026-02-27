package spannerenumservice

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/BishopFox/cloudfox/gcp/shared"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	spanner "google.golang.org/api/spanner/v1"
)

type SpannerEnumService struct {
	session *gcpinternal.SafeSession
}

func New() *SpannerEnumService {
	return &SpannerEnumService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *SpannerEnumService {
	return &SpannerEnumService{session: session}
}

// SensitiveSpannerResource represents a Spanner resource flagged as potentially sensitive.
type SensitiveSpannerResource struct {
	ProjectID  string `json:"projectId"`
	Instance   string `json:"instance"`
	Database   string `json:"database"`
	Table      string `json:"table"`
	Column     string `json:"column"`
	Category   string `json:"category"`
	RiskLevel  string `json:"riskLevel"`
	Description string `json:"description"`
}

// getSpannerService returns a Spanner service client.
func (s *SpannerEnumService) getSpannerService(ctx context.Context) (*spanner.Service, error) {
	return spanner.NewService(ctx)
}

// EnumerateSensitiveResources scans Spanner DDL for sensitive table/column names.
func (s *SpannerEnumService) EnumerateSensitiveResources(projectID string) ([]SensitiveSpannerResource, error) {
	ctx := context.Background()

	service, err := s.getSpannerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "spanner.googleapis.com")
	}

	namePatterns := shared.GetNamePatterns()
	var resources []SensitiveSpannerResource

	// List instances
	parent := fmt.Sprintf("projects/%s", projectID)
	err = service.Projects.Instances.List(parent).Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			instanceName := extractName(instance.Name)

			// List databases for this instance
			err := service.Projects.Instances.Databases.List(instance.Name).Pages(ctx, func(dbPage *spanner.ListDatabasesResponse) error {
				for _, db := range dbPage.Databases {
					dbName := extractName(db.Name)

					// Get DDL for this database
					ddlResp, err := service.Projects.Instances.Databases.GetDdl(db.Name).Context(ctx).Do()
					if err != nil {
						continue
					}

					// Parse DDL for table and column names
					for _, stmt := range ddlResp.Statements {
						tableName, columns := parseDDLStatement(stmt)
						if tableName == "" {
							continue
						}

						// Check table name
						if match := shared.MatchResourceName(tableName, namePatterns); match != nil {
							resources = append(resources, SensitiveSpannerResource{
								ProjectID:   projectID,
								Instance:    instanceName,
								Database:    dbName,
								Table:       tableName,
								Category:    match.Category,
								RiskLevel:   match.RiskLevel,
								Description: fmt.Sprintf("Table name: %s", match.Description),
							})
						}

						// Check column names
						for _, col := range columns {
							if match := shared.MatchResourceName(col, namePatterns); match != nil {
								resources = append(resources, SensitiveSpannerResource{
									ProjectID:   projectID,
									Instance:    instanceName,
									Database:    dbName,
									Table:       tableName,
									Column:      col,
									Category:    match.Category,
									RiskLevel:   match.RiskLevel,
									Description: fmt.Sprintf("Column name: %s", match.Description),
								})
							}
						}
					}
				}
				return nil
			})
			if err != nil {
				// Continue to next instance on error
				continue
			}
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "spanner.googleapis.com")
	}

	return resources, nil
}

// createTableRegex matches CREATE TABLE statements.
var createTableRegex = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(\S+)\s*\(`)

// columnRegex matches column definitions inside CREATE TABLE parentheses.
var columnRegex = regexp.MustCompile(`(?i)^\s*(\w+)\s+`)

// parseDDLStatement extracts table name and column names from a CREATE TABLE DDL statement.
func parseDDLStatement(stmt string) (string, []string) {
	match := createTableRegex.FindStringSubmatch(stmt)
	if match == nil {
		return "", nil
	}

	tableName := strings.Trim(match[1], "`\"")

	// Find the content between the first ( and the matching )
	parenStart := strings.Index(stmt, "(")
	if parenStart < 0 {
		return tableName, nil
	}

	// Find matching closing paren
	depth := 0
	parenEnd := -1
	for i := parenStart; i < len(stmt); i++ {
		switch stmt[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				parenEnd = i
			}
		}
		if parenEnd >= 0 {
			break
		}
	}

	if parenEnd < 0 {
		return tableName, nil
	}

	columnsStr := stmt[parenStart+1 : parenEnd]
	lines := strings.Split(columnsStr, ",")

	var columns []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip constraint lines
		lineLower := strings.ToLower(line)
		if strings.HasPrefix(lineLower, "constraint") ||
			strings.HasPrefix(lineLower, "primary key") ||
			strings.HasPrefix(lineLower, "foreign key") ||
			strings.HasPrefix(lineLower, "interleave") {
			continue
		}
		colMatch := columnRegex.FindStringSubmatch(line)
		if colMatch != nil {
			columns = append(columns, colMatch[1])
		}
	}

	return tableName, columns
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
