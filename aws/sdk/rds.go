package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/patrickmn/go-cache"
)

type RDSClientInterface interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

func RegisterRDSTypes() {
	gob.Register([]rdsTypes.DBInstance{})
}

func CachedRDSDescribeDBInstances(client RDSClientInterface, accountID string, region string) ([]rdsTypes.DBInstance, error) {
	var PaginationControl *string
	var instances []rdsTypes.DBInstance
	cacheKey := fmt.Sprintf("%s-rds-DescribeDBInstances-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]rdsTypes.DBInstance), nil
	}
	for {
		DescribeDBInstances, err := client.DescribeDBInstances(
			context.TODO(),
			&rds.DescribeDBInstancesInput{
				Marker: PaginationControl,
			},
			func(o *rds.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return instances, err
		}

		instances = append(instances, DescribeDBInstances.DBInstances...)

		//pagination
		if DescribeDBInstances.Marker == nil {
			break
		}
		PaginationControl = DescribeDBInstances.Marker
	}

	internal.Cache.Set(cacheKey, instances, cache.DefaultExpiration)
	return instances, nil
}
