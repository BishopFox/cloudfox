package bigqueryservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	"google.golang.org/api/iterator"
	bqapi "google.golang.org/api/bigquery/v2"
)

// AccessEntry represents an access control entry on a dataset
type AccessEntry struct {
	Role       string `json:"role"`       // OWNER, WRITER, READER
	EntityType string `json:"entityType"` // User, Group, Domain, ServiceAccount, etc.
	Entity     string `json:"entity"`     // The actual entity identifier
}

// BigqueryDataset represents a dataset in BigQuery with security-relevant fields
type BigqueryDataset struct {
	// Basic info
	DatasetID        string    `json:"datasetID"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	ProjectID        string    `json:"projectID"`
	Location         string    `json:"location"`
	FullID           string    `json:"fullID"`

	// Timestamps
	CreationTime     time.Time `json:"creationTime"`
	LastModifiedTime time.Time `json:"lastModifiedTime"`

	// Security-relevant fields
	DefaultTableExpiration     time.Duration     `json:"defaultTableExpiration"`
	DefaultPartitionExpiration time.Duration     `json:"defaultPartitionExpiration"`
	EncryptionType             string            `json:"encryptionType"`  // "Google-managed" or "CMEK"
	KMSKeyName                 string            `json:"kmsKeyName"`      // KMS key for CMEK
	Labels                     map[string]string `json:"labels"`
	StorageBillingModel        string            `json:"storageBillingModel"`
	MaxTimeTravel              time.Duration     `json:"maxTimeTravel"`

	// Access control (IAM-like)
	AccessEntries []AccessEntry `json:"accessEntries"`
	IsPublic      bool          `json:"isPublic"`      // Has allUsers or allAuthenticatedUsers
	PublicAccess  string        `json:"publicAccess"`  // "None", "allUsers", "allAuthenticatedUsers", or "Both"
}

// BigqueryTable represents a table in BigQuery with security-relevant fields
type BigqueryTable struct {
	// Basic info
	TableID     string `json:"tableID"`
	DatasetID   string `json:"datasetID"`
	ProjectID   string `json:"projectID"`
	Location    string `json:"location"`
	FullID      string `json:"fullID"`
	Description string `json:"description"`
	TableType   string `json:"tableType"` // TABLE, VIEW, MATERIALIZED_VIEW, EXTERNAL, SNAPSHOT

	// Timestamps
	CreationTime     time.Time `json:"creationTime"`
	LastModifiedTime time.Time `json:"lastModifiedTime"`
	ExpirationTime   time.Time `json:"expirationTime"`

	// Size info
	NumBytes         int64  `json:"numBytes"`
	NumLongTermBytes int64  `json:"numLongTermBytes"`
	NumRows          uint64 `json:"numRows"`

	// Security-relevant fields
	EncryptionType         string            `json:"encryptionType"` // "Google-managed" or "CMEK"
	KMSKeyName             string            `json:"kmsKeyName"`
	Labels                 map[string]string `json:"labels"`
	RequirePartitionFilter bool              `json:"requirePartitionFilter"`

	// Partitioning info
	IsPartitioned    bool   `json:"isPartitioned"`
	PartitioningType string `json:"partitioningType"` // "TIME" or "RANGE"

	// View info
	IsView       bool   `json:"isView"`
	ViewQuery    string `json:"viewQuery"`
	UseLegacySQL bool   `json:"useLegacySQL"`

	// Streaming info
	HasStreamingBuffer bool `json:"hasStreamingBuffer"`

	// IAM bindings (table-level)
	IAMBindings  []TableIAMBinding `json:"iamBindings"`
	IsPublic     bool              `json:"isPublic"`
	PublicAccess string            `json:"publicAccess"`
}

// TableIAMBinding represents an IAM binding on a table
type TableIAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// CombinedBigqueryData represents both datasets and tables within a project
type CombinedBigqueryData struct {
	Datasets []BigqueryDataset
	Tables   []BigqueryTable
}

type BigQueryService struct {
	session *gcpinternal.SafeSession
}

// New creates a new instance of BigQueryService (legacy - uses ADC directly)
func New() *BigQueryService {
	return &BigQueryService{}
}

// NewWithSession creates a BigQueryService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *BigQueryService {
	return &BigQueryService{session: session}
}

// getService returns a BigQuery REST API service client using cached session if available
func (bq *BigQueryService) getService(ctx context.Context) (*bqapi.Service, error) {
	if bq.session != nil {
		return sdk.CachedGetBigQueryService(ctx, bq.session)
	}
	return bqapi.NewService(ctx)
}

// gcloud alpha bq datasets list
// gcloud alpha bq datasets describe terragoat_dev_dataset
// gcloud alpha bq tables list --dataset terragoat_dev_dataset
// gcloud alpha bq tables describe bar --dataset terragoat_dev_dataset

// BigqueryDatasetsAndTables retrieves all datasets and their tables for a given projectID
func (bq *BigQueryService) BigqueryDatasetsAndTables(projectID string) (CombinedBigqueryData, error) {
	// Initialize the combined struct to hold datasets and tables
	combinedData := CombinedBigqueryData{}

	// Retrieve all datasets
	datasets, err := bq.BigqueryDatasets(projectID)
	if err != nil {
		return combinedData, err
	}
	combinedData.Datasets = datasets

	// Iterate over each dataset to retrieve its tables
	for _, dataset := range datasets {
		tables, err := bq.BigqueryTables(projectID, dataset.DatasetID)
		if err != nil {
			return combinedData, err
		}
		combinedData.Tables = append(combinedData.Tables, tables...)
	}

	return combinedData, nil
}

// BigqueryDatasets retrieves datasets from the given projectID across all locations
func (bq *BigQueryService) BigqueryDatasets(projectID string) ([]BigqueryDataset, error) {
	ctx := context.Background()
	var client *bigquery.Client
	var err error

	if bq.session != nil {
		client, err = bigquery.NewClient(ctx, projectID, bq.session.GetClientOption())
	} else {
		client, err = bigquery.NewClient(ctx, projectID)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
	}
	defer client.Close()

	var datasets []BigqueryDataset
	it := client.Datasets(ctx)
	for {
		ds, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
		}
		meta, err := ds.Metadata(ctx)
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
		}

		dataset := BigqueryDataset{
			DatasetID:                  ds.DatasetID,
			Name:                       meta.Name,
			Description:                meta.Description,
			ProjectID:                  projectID,
			Location:                   meta.Location,
			FullID:                     meta.FullID,
			CreationTime:               meta.CreationTime,
			LastModifiedTime:           meta.LastModifiedTime,
			DefaultTableExpiration:     meta.DefaultTableExpiration,
			DefaultPartitionExpiration: meta.DefaultPartitionExpiration,
			Labels:                     meta.Labels,
			StorageBillingModel:        meta.StorageBillingModel,
			MaxTimeTravel:              meta.MaxTimeTravel,
		}

		// Parse encryption
		if meta.DefaultEncryptionConfig != nil && meta.DefaultEncryptionConfig.KMSKeyName != "" {
			dataset.EncryptionType = "CMEK"
			dataset.KMSKeyName = meta.DefaultEncryptionConfig.KMSKeyName
		} else {
			dataset.EncryptionType = "Google-managed"
		}

		// Parse access entries
		accessEntries, isPublic, publicAccess := parseDatasetAccess(meta.Access)
		dataset.AccessEntries = accessEntries
		dataset.IsPublic = isPublic
		dataset.PublicAccess = publicAccess

		datasets = append(datasets, dataset)
	}
	return datasets, nil
}

// parseDatasetAccess converts BigQuery access entries to our format and checks for public access
func parseDatasetAccess(access []*bigquery.AccessEntry) ([]AccessEntry, bool, string) {
	var entries []AccessEntry
	isPublic := false
	hasAllUsers := false
	hasAllAuthenticatedUsers := false

	for _, a := range access {
		if a == nil {
			continue
		}

		entry := AccessEntry{
			Role:       string(a.Role),
			EntityType: entityTypeToString(a.EntityType),
			Entity:     a.Entity,
		}

		// Check for special access (views, routines, datasets)
		if a.View != nil {
			entry.EntityType = "View"
			entry.Entity = fmt.Sprintf("%s.%s.%s", a.View.ProjectID, a.View.DatasetID, a.View.TableID)
		}
		if a.Routine != nil {
			entry.EntityType = "Routine"
			entry.Entity = fmt.Sprintf("%s.%s.%s", a.Routine.ProjectID, a.Routine.DatasetID, a.Routine.RoutineID)
		}
		if a.Dataset != nil {
			entry.EntityType = "Dataset"
			entry.Entity = fmt.Sprintf("%s.%s", a.Dataset.Dataset.ProjectID, a.Dataset.Dataset.DatasetID)
		}

		// Check for public access
		if a.EntityType == bigquery.SpecialGroupEntity {
			if a.Entity == "allUsers" || strings.Contains(strings.ToLower(a.Entity), "allusers") {
				hasAllUsers = true
				isPublic = true
			}
			if a.Entity == "allAuthenticatedUsers" || strings.Contains(strings.ToLower(a.Entity), "allauthenticatedusers") {
				hasAllAuthenticatedUsers = true
				isPublic = true
			}
		}

		entries = append(entries, entry)
	}

	// Determine public access level
	publicAccess := "None"
	if hasAllUsers && hasAllAuthenticatedUsers {
		publicAccess = "allUsers + allAuthenticatedUsers"
	} else if hasAllUsers {
		publicAccess = "allUsers"
	} else if hasAllAuthenticatedUsers {
		publicAccess = "allAuthenticatedUsers"
	}

	return entries, isPublic, publicAccess
}

// entityTypeToString converts BigQuery EntityType to a readable string
func entityTypeToString(et bigquery.EntityType) string {
	switch et {
	case bigquery.DomainEntity:
		return "Domain"
	case bigquery.GroupEmailEntity:
		return "Group"
	case bigquery.UserEmailEntity:
		return "User"
	case bigquery.SpecialGroupEntity:
		return "SpecialGroup"
	case bigquery.ViewEntity:
		return "View"
	case bigquery.IAMMemberEntity:
		return "IAMMember"
	case bigquery.RoutineEntity:
		return "Routine"
	case bigquery.DatasetEntity:
		return "Dataset"
	default:
		return "Unknown"
	}
}

// BigqueryTables retrieves tables from the given projectID and dataset across all locations
func (bq *BigQueryService) BigqueryTables(projectID string, datasetID string) ([]BigqueryTable, error) {
	ctx := context.Background()
	var client *bigquery.Client
	var err error

	if bq.session != nil {
		client, err = bigquery.NewClient(ctx, projectID, bq.session.GetClientOption())
	} else {
		client, err = bigquery.NewClient(ctx, projectID)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
	}
	defer client.Close()

	// Create API service for IAM calls using cached wrapper
	apiService, err := bq.getService(ctx)
	if err != nil {
		// Continue without IAM if service creation fails
		apiService = nil
	}

	var tables []BigqueryTable
	ds := client.Dataset(datasetID)
	it := ds.Tables(ctx)
	for {
		table, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
		}
		meta, err := table.Metadata(ctx)
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
		}

		tbl := BigqueryTable{
			TableID:                table.TableID,
			DatasetID:              datasetID,
			ProjectID:              projectID,
			Location:               meta.Location,
			FullID:                 meta.FullID,
			Description:            meta.Description,
			TableType:              tableTypeToString(meta.Type),
			CreationTime:           meta.CreationTime,
			LastModifiedTime:       meta.LastModifiedTime,
			ExpirationTime:         meta.ExpirationTime,
			NumBytes:               meta.NumBytes,
			NumLongTermBytes:       meta.NumLongTermBytes,
			NumRows:                meta.NumRows,
			Labels:                 meta.Labels,
			RequirePartitionFilter: meta.RequirePartitionFilter,
		}

		// Parse encryption
		if meta.EncryptionConfig != nil && meta.EncryptionConfig.KMSKeyName != "" {
			tbl.EncryptionType = "CMEK"
			tbl.KMSKeyName = meta.EncryptionConfig.KMSKeyName
		} else {
			tbl.EncryptionType = "Google-managed"
		}

		// Parse partitioning
		if meta.TimePartitioning != nil {
			tbl.IsPartitioned = true
			tbl.PartitioningType = "TIME"
		} else if meta.RangePartitioning != nil {
			tbl.IsPartitioned = true
			tbl.PartitioningType = "RANGE"
		}

		// Parse view info
		if meta.ViewQuery != "" {
			tbl.IsView = true
			tbl.ViewQuery = meta.ViewQuery
			tbl.UseLegacySQL = meta.UseLegacySQL
		}

		// Check for streaming buffer
		if meta.StreamingBuffer != nil {
			tbl.HasStreamingBuffer = true
		}

		// Get table-level IAM policy
		if apiService != nil {
			iamBindings, isPublic, publicAccess := bq.getTableIAMPolicy(ctx, apiService, projectID, datasetID, table.TableID)
			tbl.IAMBindings = iamBindings
			tbl.IsPublic = isPublic
			tbl.PublicAccess = publicAccess
		}

		tables = append(tables, tbl)
	}
	return tables, nil
}

// getTableIAMPolicy retrieves IAM policy for a specific table
func (bq *BigQueryService) getTableIAMPolicy(ctx context.Context, apiService *bqapi.Service, projectID, datasetID, tableID string) ([]TableIAMBinding, bool, string) {
	var bindings []TableIAMBinding
	isPublic := false
	hasAllUsers := false
	hasAllAuthenticatedUsers := false

	resource := fmt.Sprintf("projects/%s/datasets/%s/tables/%s", projectID, datasetID, tableID)
	policy, err := apiService.Tables.GetIamPolicy(resource, &bqapi.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		// IAM not available or permission denied - return empty
		return bindings, false, "None"
	}

	for _, binding := range policy.Bindings {
		iamBinding := TableIAMBinding{
			Role:    binding.Role,
			Members: binding.Members,
		}
		bindings = append(bindings, iamBinding)

		// Check for public access
		for _, member := range binding.Members {
			if member == "allUsers" {
				hasAllUsers = true
				isPublic = true
			}
			if member == "allAuthenticatedUsers" {
				hasAllAuthenticatedUsers = true
				isPublic = true
			}
		}
	}

	// Determine public access level
	publicAccess := "None"
	if hasAllUsers && hasAllAuthenticatedUsers {
		publicAccess = "allUsers + allAuthenticatedUsers"
	} else if hasAllUsers {
		publicAccess = "allUsers"
	} else if hasAllAuthenticatedUsers {
		publicAccess = "allAuthenticatedUsers"
	}

	return bindings, isPublic, publicAccess
}

// tableTypeToString converts BigQuery TableType to a readable string
func tableTypeToString(tt bigquery.TableType) string {
	switch tt {
	case bigquery.RegularTable:
		return "TABLE"
	case bigquery.ViewTable:
		return "VIEW"
	case bigquery.ExternalTable:
		return "EXTERNAL"
	case bigquery.MaterializedView:
		return "MATERIALIZED_VIEW"
	case bigquery.Snapshot:
		return "SNAPSHOT"
	default:
		return "UNKNOWN"
	}
}

// GetMemberType extracts the member type from entity info
func GetMemberType(entityType string, entity string) string {
	switch entityType {
	case "User":
		return "User"
	case "Group":
		return "Group"
	case "Domain":
		return "Domain"
	case "SpecialGroup":
		if strings.Contains(strings.ToLower(entity), "allusers") {
			return "PUBLIC"
		}
		if strings.Contains(strings.ToLower(entity), "allauthenticatedusers") {
			return "ALL_AUTHENTICATED"
		}
		return "SpecialGroup"
	case "IAMMember":
		if strings.HasPrefix(entity, "serviceAccount:") {
			return "ServiceAccount"
		}
		if strings.HasPrefix(entity, "user:") {
			return "User"
		}
		if strings.HasPrefix(entity, "group:") {
			return "Group"
		}
		return "IAMMember"
	case "View":
		return "AuthorizedView"
	case "Routine":
		return "AuthorizedRoutine"
	case "Dataset":
		return "AuthorizedDataset"
	default:
		return "Unknown"
	}
}
