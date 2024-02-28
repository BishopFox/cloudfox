package sdk

import (
	"context"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptuneTypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"

	"github.com/patrickmn/go-cache"
)

type NeptuneClientInterface interface {
	DescribeDBClusters(ctx context.Context, params *neptune.DescribeDBClustersInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error)
}

func init() {
	//gob.RegisterName("neptune.DBCluster", []neptuneTypes.DBCluster{})
}

func CachedNeptuneDescribeDBClusters(client NeptuneClientInterface, accountID string, region string) ([]neptuneTypes.DBCluster, error) {
	var paginationControl *string
	var clusters []neptuneTypes.DBCluster
	cacheKey := fmt.Sprintf("%s-neptune-DescribeDBClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]neptuneTypes.DBCluster), nil
	}
	for {
		describeDBClusters, err := client.DescribeDBClusters(
			context.TODO(),
			&neptune.DescribeDBClustersInput{
				Marker: paginationControl,
			},
			func(o *neptune.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return clusters, err
		}

		clusters = append(clusters, describeDBClusters.DBClusters...)

		//pagination
		if describeDBClusters.Marker == nil {
			break
		}
		paginationControl = describeDBClusters.Marker
	}

	internal.Cache.Set(cacheKey, clusters, cache.DefaultExpiration)
	return clusters, nil
}
