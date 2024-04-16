package bigqueryservice

import (
	"context"
	"time"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

// BigqueryDataset represents a dataset in BigQuery
type BigqueryDataset struct {
	DatasetID        string
	Location         string
	CreationTime     time.Time
	LastModifiedTime time.Time
	Description      string
	Name             string
	ProjectID        string
}

// BigqueryTable represents a table in BigQuery
type BigqueryTable struct {
	TableID          string
	DatasetID        string
	Location         string
	CreationTime     time.Time
	LastModifiedTime time.Time
	NumBytes         int64
	Description      string
	ProjectID        string
}

// CombinedBigqueryData represents both datasets and tables within a project
type CombinedBigqueryData struct {
	Datasets []BigqueryDataset
	Tables   []BigqueryTable
}

type BigQueryService struct {
	// Placeholder for any required services or configuration
}

// New creates a new instance of BigQueryService
func New() *BigQueryService {
	return &BigQueryService{}
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
	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		meta, err := ds.Metadata(ctx)
		if err != nil {
			return nil, err
		}
		datasets = append(datasets, BigqueryDataset{
			DatasetID:        ds.DatasetID,
			Location:         meta.Location,
			CreationTime:     meta.CreationTime,
			LastModifiedTime: meta.LastModifiedTime,
			Description:      meta.Description,
			Name:             meta.Name,
			ProjectID:        projectID,
		})
	}
	return datasets, nil
}

// BigqueryTables retrieves tables from the given projectID and dataset across all locations
func (bq *BigQueryService) BigqueryTables(projectID string, datasetID string) ([]BigqueryTable, error) {
	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var tables []BigqueryTable
	ds := client.Dataset(datasetID)
	it := ds.Tables(ctx)
	for {
		table, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		meta, err := table.Metadata(ctx)
		if err != nil {
			return nil, err
		}
		tables = append(tables, BigqueryTable{
			TableID:          table.TableID,
			DatasetID:        datasetID,
			Location:         meta.Location,
			CreationTime:     meta.CreationTime,
			LastModifiedTime: meta.LastModifiedTime,
			NumBytes:         meta.NumBytes,
			Description:      meta.Description,
			ProjectID:        projectID,
		})
	}
	return tables, nil
}
