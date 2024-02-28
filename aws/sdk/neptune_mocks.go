package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptuneTypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
)

type MockedNeptuneClient struct {
}

func (m *MockedNeptuneClient) DescribeDBClusters(ctx context.Context, params *neptune.DescribeDBClustersInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error) {
	return &neptune.DescribeDBClustersOutput {
		DBClusters: []neptuneTypes.DBCluster{
			{
				DBClusterIdentifier: aws.String("db1"),
				Engine:              aws.String("neptune"),
				EngineVersion:       aws.String("1.3.0.0"),
				ClusterCreateTime:   aws.Time(time.Now()),
				MasterUsername:      aws.String("neptune"),
			},
			{
				DBClusterIdentifier: aws.String("db2"),
				Engine:              aws.String("neptune"),
				EngineVersion:       aws.String("1.3.0.0"),
				ClusterCreateTime:   aws.Time(time.Now()),
				MasterUsername:      aws.String("neptune"),
			},
		},
	}, nil
}
