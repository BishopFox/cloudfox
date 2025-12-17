package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrTypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type AWSEMRClientInterface interface {
	ListClusters(context.Context, *emr.ListClustersInput, ...func(*emr.Options)) (*emr.ListClustersOutput, error)
	ListInstances(context.Context, *emr.ListInstancesInput, ...func(*emr.Options)) (*emr.ListInstancesOutput, error)
}

func init() {
	gob.Register([]emrTypes.ClusterSummary{})

	//need to do this to avoid conflicts with the Instance type in the ec2 package
	type EMRInstance emrTypes.Instance
	gob.Register([]EMRInstance{})
}

func CachedEMRListClusters(client AWSEMRClientInterface, accountID string, region string) ([]emrTypes.ClusterSummary, error) {
	var PaginationControl *string
	var clusters []emrTypes.ClusterSummary
	cacheKey := fmt.Sprintf("%s-emr-ListClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "emr:ListClusters",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]emrTypes.ClusterSummary), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "emr:ListClusters",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		ListClusters, err := client.ListClusters(
			context.TODO(),
			&emr.ListClustersInput{
				Marker: PaginationControl,
			},
			func(o *emr.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return clusters, err
		}

		clusters = append(clusters, ListClusters.Clusters...)

		//pagination
		if ListClusters.Marker == nil {
			break
		}
		PaginationControl = ListClusters.Marker
	}

	internal.Cache.Set(cacheKey, clusters, cache.DefaultExpiration)
	return clusters, nil
}

func CachedEMRListInstances(client AWSEMRClientInterface, accountID string, region string, clusterID string) ([]emrTypes.Instance, error) {
	var PaginationControl *string
	var instances []emrTypes.Instance
	cacheKey := fmt.Sprintf("%s-emr-ListInstances-%s-%s", accountID, region, clusterID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":       "emr:ListInstances",
			"account":   accountID,
			"region":    region,
			"clusterId": clusterID,
			"cache":     "hit",
		}).Info("AWS API call")
		return cached.([]emrTypes.Instance), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":       "emr:ListInstances",
		"account":   accountID,
		"region":    region,
		"clusterId": clusterID,
		"cache":     "miss",
	}).Info("AWS API call")
	for {
		ListInstances, err := client.ListInstances(
			context.TODO(),
			&emr.ListInstancesInput{
				ClusterId: &clusterID,
				Marker:    PaginationControl,
			},
			func(o *emr.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return instances, err
		}

		instances = append(instances, ListInstances.Instances...)

		//pagination
		if ListInstances.Marker == nil {
			break
		}
		PaginationControl = ListInstances.Marker
	}

	internal.Cache.Set(cacheKey, instances, cache.DefaultExpiration)
	return instances, nil
}
