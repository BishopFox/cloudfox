package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbTypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
)

type MockedAWSDocsDBClient struct {
}

func (m *MockedAWSDocsDBClient) DescribeDBClusters(ctx context.Context, input *docdb.DescribeDBClustersInput, options ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error) {
	return &docdb.DescribeDBClustersOutput{
		DBClusters: []docdbTypes.DBCluster{
			{
				DBClusterIdentifier: aws.String("cluster1"),
			},
			{
				DBClusterIdentifier: aws.String("cluster2"),
			},
		},
	}, nil
}
