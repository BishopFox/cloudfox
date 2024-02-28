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
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
}

func init() {
	gob.Register([]rdsTypes.DBInstance{})
	gob.Register([]rdsTypes.DBCluster{})

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

func CachedRDSDescribeDBClusters(client RDSClientInterface, accountID string, region string) ([]rdsTypes.DBCluster, error) {
	var PaginationControl *string
	var clusters []rdsTypes.DBCluster
	cacheKey := fmt.Sprintf("%s-rds-DescribeDBClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]rdsTypes.DBCluster), nil
	}
	for {
		DescribeDBClusters, err := client.DescribeDBClusters(
			context.TODO(),
			&rds.DescribeDBClustersInput{
				Marker: PaginationControl,
			},
			func(o *rds.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return clusters, err
		}

		clusters = append(clusters, DescribeDBClusters.DBClusters...)

		//pagination
		if DescribeDBClusters.Marker == nil {
			break
		}
		PaginationControl = DescribeDBClusters.Marker
	}

	internal.Cache.Set(cacheKey, clusters, cache.DefaultExpiration)
	return clusters, nil
}
