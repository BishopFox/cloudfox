package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type MockedRDSClient struct {
}

func (m *MockedRDSClient) DescribeDBInstances(ctx context.Context, input *rds.DescribeDBInstancesInput, options ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{
		DBInstances: []rdsTypes.DBInstance{
			{
				DBInstanceIdentifier: aws.String("db1"),
				Engine:               aws.String("postgres"),
				EngineVersion:        aws.String("13.3"),
				InstanceCreateTime:   aws.Time(time.Now()),
				MasterUsername:       aws.String("postgres"),
				Endpoint: &rdsTypes.Endpoint{
					Address: aws.String("db1-instances-1.blah.us-west-2.rds.amazonaws.com"),
					Port:    aws.Int32(5432),
				},
			},
			{
				DBInstanceIdentifier: aws.String("db2"),
				Engine:               aws.String("postgres"),
				EngineVersion:        aws.String("13.3"),
				InstanceCreateTime:   aws.Time(time.Now()),
				MasterUsername:       aws.String("postgres"),
				Endpoint: &rdsTypes.Endpoint{
					Address: aws.String("db2-instances-1.blah.us-west-2.rds.amazonaws.com"),
					Port:    aws.Int32(5432),
				},
			},
		},
	}, nil
}

func (m *MockedRDSClient) DescribeDBClusters(ctx context.Context, input *rds.DescribeDBClustersInput, options ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	return &rds.DescribeDBClustersOutput{
		DBClusters: []rdsTypes.DBCluster{
			{
				DBClusterIdentifier: aws.String("db1"),
				Engine:              aws.String("aurora-postgresql"),
				EngineVersion:       aws.String("13.3"),
				Endpoint:            aws.String("db1.cluster-123456789012.us-west-2.rds.amazonaws.com"),
				ClusterCreateTime:   aws.Time(time.Now()),
				MasterUsername:      aws.String("postgres"),
				Port:                aws.Int32(5432),
				AssociatedRoles:     nil,
			},
			{
				DBClusterIdentifier: aws.String("db2"),
				Engine:              aws.String("aurora-postgresql"),
				EngineVersion:       aws.String("13.3"),
				Endpoint:            aws.String("db2.cluster-123456789012.us-west-2.rds.amazonaws.com"),
				ClusterCreateTime:   aws.Time(time.Now()),
				MasterUsername:      aws.String("postgres"),
				Port:                aws.Int32(5432),
				AssociatedRoles:     nil,
			},
			{
				DBClusterIdentifier: aws.String("db3"),
				Engine:              aws.String("neptune"),
				EngineVersion:       aws.String("1.2.1.0"),
				Endpoint:            aws.String("db3.cluster-123456789012.us-west-2.neptune.amazonaws.com"),
				MasterUsername:      aws.String("neptune"),
				Port:                aws.Int32(8182),
				AssociatedRoles: []rdsTypes.DBClusterRole{
					{
						RoleArn: aws.String("arn:aws:iam::123456789012:role/NeptuneRole"),
						Status:  aws.String("active"),
					},
				},
			},
			{
				DBClusterIdentifier: aws.String("db4"),
				Engine:              aws.String("docsdb"),
				EngineVersion:       aws.String("4.0.0"),
				Endpoint:            aws.String("db4.cluster-123456789012.us-west-2.docdb.amazonaws.com"),
				MasterUsername:      aws.String("docsdb"),
				Port:                aws.Int32(27017),
				AssociatedRoles:     nil,
			},
		},
	}, nil
}
