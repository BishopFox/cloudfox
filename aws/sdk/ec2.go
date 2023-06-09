package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/patrickmn/go-cache"
)

type EC2ClientInterface interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

func RegisterEC2Types() {
	gob.Register([]ec2Types.Instance{})
}

func CachedEC2DescribeInstances(client EC2ClientInterface, accountID string, region string) ([]ec2Types.Instance, error) {
	var PaginationControl *string
	var instances []ec2Types.Instance
	cacheKey := fmt.Sprintf("%s-ec2-DescribeInstances-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]ec2Types.Instance), nil
	}
	for {
		DescribeInstances, err := client.DescribeInstances(
			context.TODO(),
			&ec2.DescribeInstancesInput{
				NextToken: PaginationControl,
			},
			func(o *ec2.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return instances, err
		}

		for _, reservation := range DescribeInstances.Reservations {
			instances = append(instances, reservation.Instances...)
		}

		//pagination
		if DescribeInstances.NextToken == nil {
			break
		}
		PaginationControl = DescribeInstances.NextToken
	}

	internal.Cache.Set(cacheKey, instances, cache.DefaultExpiration)
	return instances, nil
}
