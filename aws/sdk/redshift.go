package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshiftTypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/patrickmn/go-cache"
)

type AWSRedShiftClientInterface interface {
	DescribeClusters(context.Context, *redshift.DescribeClustersInput, ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
}

func init() {
	gob.Register([]redshiftTypes.Cluster{})

}

func CachedRedShiftDescribeClusters(client AWSRedShiftClientInterface, accountID string, region string) ([]redshiftTypes.Cluster, error) {
	var PaginationControl *string
	var clusters []redshiftTypes.Cluster
	cacheKey := fmt.Sprintf("%s-redshift-DescribeClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]redshiftTypes.Cluster), nil
	}
	for {
		DescribeClusters, err := client.DescribeClusters(
			context.TODO(),
			&redshift.DescribeClustersInput{
				Marker: PaginationControl,
			},
			func(o *redshift.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return clusters, err
		}

		clusters = append(clusters, DescribeClusters.Clusters...)

		//pagination
		if DescribeClusters.Marker == nil {
			break
		}
		PaginationControl = DescribeClusters.Marker
	}

	internal.Cache.Set(cacheKey, clusters, cache.DefaultExpiration)
	return clusters, nil
}
