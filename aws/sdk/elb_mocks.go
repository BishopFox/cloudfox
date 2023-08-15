package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbTypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
)

type MockedElbClient struct {
}

func (m *MockedElbClient) DescribeLoadBalancers(ctx context.Context, input *elasticloadbalancing.DescribeLoadBalancersInput, options ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancersOutput, error) {
	return &elasticloadbalancing.DescribeLoadBalancersOutput{
		LoadBalancerDescriptions: []elbTypes.LoadBalancerDescription{
			{
				LoadBalancerName: aws.String("elb1"),
				DNSName:          aws.String("elb1"),
				Instances: []elbTypes.Instance{
					{
						InstanceId: aws.String("i-1234567890abcdef0"),
					},
				},
			},
			{
				LoadBalancerName: aws.String("elb2"),
				DNSName:          aws.String("elb2"),
				Instances: []elbTypes.Instance{
					{
						InstanceId: aws.String("i-1234567890abcdef1"),
					},
				},
			},
		},
	}, nil
}
