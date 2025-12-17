package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticacheTypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type AWSElastiCacheClientInterface interface {
	DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error)
}

func init() {
	gob.Register([]elasticacheTypes.CacheCluster{})

}

func CachedElastiCacheDescribeCacheClusters(client AWSElastiCacheClientInterface, accountID string, region string) ([]elasticacheTypes.CacheCluster, error) {
	var PaginationControl *string
	var clusters []elasticacheTypes.CacheCluster
	cacheKey := fmt.Sprintf("%s-elasticache-DescribeCacheClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "elasticache:DescribeCacheClusters",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]elasticacheTypes.CacheCluster), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "elasticache:DescribeCacheClusters",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeCacheClusters, err := client.DescribeCacheClusters(
			context.TODO(),
			&elasticache.DescribeCacheClustersInput{
				Marker: PaginationControl,
			},
			func(o *elasticache.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return clusters, err
		}

		clusters = append(clusters, DescribeCacheClusters.CacheClusters...)

		//pagination
		if DescribeCacheClusters.Marker == nil {
			break
		}
		PaginationControl = DescribeCacheClusters.Marker
	}

	internal.Cache.Set(cacheKey, clusters, cache.DefaultExpiration)
	return clusters, nil
}
