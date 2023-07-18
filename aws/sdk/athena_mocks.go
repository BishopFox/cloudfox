package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenaTypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
)

type MockedAWSAthenaClient struct {
}

func (m *MockedAWSAthenaClient) ListDatabases(ctx context.Context, input *athena.ListDatabasesInput, options ...func(*athena.Options)) (*athena.ListDatabasesOutput, error) {
	return &athena.ListDatabasesOutput{
		DatabaseList: []athenaTypes.Database{
			{
				Name: aws.String("db1"),
			},
			{
				Name: aws.String("db2"),
			},
		},
	}, nil
}

func (m *MockedAWSAthenaClient) ListDataCatalogs(ctx context.Context, input *athena.ListDataCatalogsInput, options ...func(*athena.Options)) (*athena.ListDataCatalogsOutput, error) {
	return &athena.ListDataCatalogsOutput{
		DataCatalogsSummary: []athenaTypes.DataCatalogSummary{
			{
				CatalogName: aws.String("catalog1"),
			},
			{
				CatalogName: aws.String("catalog2"),
			},
		},
	}, nil
}
