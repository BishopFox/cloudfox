package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	eksTypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

type MockedAWSEksClient struct {
}

func (m *MockedAWSEksClient) ListClusters(ctx context.Context, input *eks.ListClustersInput, options ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	return &eks.ListClustersOutput{
		Clusters: []string{
			"cluster1",
			"cluster2",
		},
	}, nil
}

func (m *MockedAWSEksClient) DescribeCluster(ctx context.Context, input *eks.DescribeClusterInput, options ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	return &eks.DescribeClusterOutput{
		Cluster: &eksTypes.Cluster{
			Arn:             aws.String("arn:aws:eks:us-east-1:123456789012:cluster/cluster1"),
			Endpoint:        aws.String("https://cluster1.us-east-1.eks.amazonaws.com"),
			Name:            aws.String("cluster1"),
			PlatformVersion: aws.String("eks.1"),
			Version:         aws.String("1.18"),
			RoleArn:         aws.String("arn:aws:iam::123456789012:role/eks-role"),
		},
	}, nil
}

func (m *MockedAWSEksClient) ListNodegroups(ctx context.Context, input *eks.ListNodegroupsInput, options ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	return &eks.ListNodegroupsOutput{
		Nodegroups: []string{
			"nodegroup1",
			"nodegroup2",
		},
	}, nil
}

func (m *MockedAWSEksClient) DescribeNodegroup(ctx context.Context, input *eks.DescribeNodegroupInput, options ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	return &eks.DescribeNodegroupOutput{
		Nodegroup: &eksTypes.Nodegroup{
			ClusterName:   aws.String("cluster1"),
			NodeRole:      aws.String("arn:aws:iam::123456789012:role/eks-role"),
			NodegroupName: aws.String("nodegroup1"),
			NodegroupArn:  aws.String("arn:aws:eks:us-east-1:123456789012:nodegroup/cluster1/nodegroup1"),
		},
	}, nil
}
