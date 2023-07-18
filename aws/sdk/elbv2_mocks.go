package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2Types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

type MockedElbv2Client struct {
}

func (m *MockedElbv2Client) DescribeLoadBalancers(ctx context.Context, input *elasticloadbalancingv2.DescribeLoadBalancersInput, options ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
		LoadBalancers: []elbv2Types.LoadBalancer{
			{
				LoadBalancerArn:       aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188"),
				DNSName:               aws.String("my-load-balancer-424835706.us-east-1.elb.amazonaws.com"),
				CanonicalHostedZoneId: aws.String("Z2P70J7EXAMPLE"),
				CreatedTime:           aws.Time(time.Now()),
				LoadBalancerName:      aws.String("my-load-balancer"),
				Scheme:                elbv2Types.LoadBalancerSchemeEnumInternetFacing,
				VpcId:                 aws.String("vpc-3ac0fb5f"),
				State: &elbv2Types.LoadBalancerState{
					Code:   elbv2Types.LoadBalancerStateEnumActive,
					Reason: aws.String(""),
				},
				Type: elbv2Types.LoadBalancerTypeEnumApplication,
				AvailabilityZones: []elbv2Types.AvailabilityZone{
					{
						ZoneName: aws.String("us-east-1a"),
						SubnetId: aws.String("subnet-8360a9e7"),
						LoadBalancerAddresses: []elbv2Types.LoadBalancerAddress{
							{
								IpAddress: aws.String("1.2.3.4"),
							},
						},
					},
					{
						ZoneName: aws.String("us-east-1b"),
						SubnetId: aws.String("subnet-b7d581c0"),
						LoadBalancerAddresses: []elbv2Types.LoadBalancerAddress{
							{
								IpAddress: aws.String("2.3.4.5"),
							},
						},
					},
				},
				SecurityGroups: []string{
					"sg-5943793c",
				},
				IpAddressType: elbv2Types.IpAddressTypeDualstack,
			},
		},
	}, nil
}
