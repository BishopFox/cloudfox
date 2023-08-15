package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshiftTypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
)

type MockedRedshiftClient struct {
}

func (m *MockedRedshiftClient) DescribeClusters(ctx context.Context, input *redshift.DescribeClustersInput, options ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	return &redshift.DescribeClustersOutput{
		Clusters: []redshiftTypes.Cluster{
			{
				ClusterIdentifier:   aws.String("cluster1"),
				ClusterNamespaceArn: aws.String("arn:aws:redshift:us-east-1:123456789012:cluster:cluster1"),
				DBName:              aws.String("db1"),
				Endpoint: &redshiftTypes.Endpoint{
					Address: aws.String("cluster1.us-east-1.redshift.amazonaws.com"),
					Port:    5439,
				},
			},
			{
				ClusterIdentifier:   aws.String("cluster2"),
				ClusterNamespaceArn: aws.String("arn:aws:redshift:us-east-1:123456789012:cluster:cluster2"),
				DBName:              aws.String("db2"),
				Endpoint: &redshiftTypes.Endpoint{
					Address: aws.String("cluster2.us-east-1.redshift.amazonaws.com"),
					Port:    5439,
				},
			},
		},
	}, nil
}
