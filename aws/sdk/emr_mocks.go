package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrTypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
)

type MockedEMRClient struct {
}

func (m *MockedEMRClient) ListClusters(ctx context.Context, input *emr.ListClustersInput, options ...func(*emr.Options)) (*emr.ListClustersOutput, error) {
	return &emr.ListClustersOutput{
		Clusters: []emrTypes.ClusterSummary{
			{
				Id: aws.String("cluster1"),
			},
			{
				Id: aws.String("cluster2"),
			},
		},
	}, nil
}

func (m *MockedEMRClient) ListInstances(ctx context.Context, input *emr.ListInstancesInput, options ...func(*emr.Options)) (*emr.ListInstancesOutput, error) {
	return &emr.ListInstancesOutput{
		Instances: []emrTypes.Instance{
			{
				Id:               aws.String("instance1"),
				InstanceType:     aws.String("m5.xlarge"),
				Ec2InstanceId:    aws.String("i-1234567890"),
				PrivateDnsName:   aws.String("ip-10-0-0-1.ec2.internal"),
				PublicDnsName:    aws.String("ec2-1-2-3-4.compute-1.amazonaws.com"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PublicIpAddress:  aws.String("1.2.3.4"),
			},
			{
				Id: aws.String("instance2"),
			},
		},
	}, nil
}
