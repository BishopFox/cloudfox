package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailTypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
)

type MockedLightsailClient struct {
}

func (m *MockedLightsailClient) GetInstances(ctx context.Context, input *lightsail.GetInstancesInput, options ...func(*lightsail.Options)) (*lightsail.GetInstancesOutput, error) {
	return &lightsail.GetInstancesOutput{
		Instances: []lightsailTypes.Instance{
			{
				BlueprintId: aws.String("blueprint1"),
				BundleId:    aws.String("bundle1"),
				CreatedAt:   aws.Time(time.Now()),
				Location: &lightsailTypes.ResourceLocation{
					AvailabilityZone: aws.String("us-east-1a"),
					RegionName:       lightsailTypes.RegionNameUsEast1,
				},
				Name: aws.String("instance1"),
				Networking: &lightsailTypes.InstanceNetworking{
					MonthlyTransfer: &lightsailTypes.MonthlyTransfer{
						GbPerMonthAllocated: aws.Int32(1),
					},
				},
				PrivateIpAddress: aws.String("10.1.1.1"),
				PublicIpAddress:  aws.String("1.2.3.4"),
			},
			{
				BlueprintId: aws.String("blueprint2"),
				BundleId:    aws.String("bundle2"),
				CreatedAt:   aws.Time(time.Now()),
				Location: &lightsailTypes.ResourceLocation{
					AvailabilityZone: aws.String("us-east-1b"),
					RegionName:       lightsailTypes.RegionNameUsEast1,
				},
				Name: aws.String("instance2"),
				Networking: &lightsailTypes.InstanceNetworking{
					MonthlyTransfer: &lightsailTypes.MonthlyTransfer{
						GbPerMonthAllocated: aws.Int32(2),
					},
				},
				PrivateIpAddress: aws.String("10.2.2.2"),
				PublicIpAddress:  aws.String("2.3.4.4"),
			},
		},
	}, nil

}

func (m *MockedLightsailClient) GetContainerServices(ctx context.Context, input *lightsail.GetContainerServicesInput, options ...func(*lightsail.Options)) (*lightsail.GetContainerServicesOutput, error) {
	return &lightsail.GetContainerServicesOutput{
		ContainerServices: []lightsailTypes.ContainerService{
			{
				Arn: aws.String("arn1"),
				Location: &lightsailTypes.ResourceLocation{
					AvailabilityZone: aws.String("us-east-1a"),
					RegionName:       lightsailTypes.RegionNameUsEast1,
				},
				Url:               aws.String("https://container1"),
				PrivateDomainName: aws.String("container1"),
			},
			{
				Arn: aws.String("arn2"),
				Location: &lightsailTypes.ResourceLocation{
					AvailabilityZone: aws.String("us-east-1a"),
					RegionName:       lightsailTypes.RegionNameUsEast1,
				},
				Url:               aws.String("https://container2"),
				PrivateDomainName: aws.String("container2"),
			},
		},
	}, nil
}
