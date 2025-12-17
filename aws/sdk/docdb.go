package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbTypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type DocDBClientInterface interface {
	DescribeGlobalClusters(context.Context, *docdb.DescribeGlobalClustersInput, ...func(*docdb.Options)) (*docdb.DescribeGlobalClustersOutput, error)
	DescribeDBClusters(context.Context, *docdb.DescribeDBClustersInput, ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error)
	DescribeDBInstances(context.Context, *docdb.DescribeDBInstancesInput, ...func(*docdb.Options)) (*docdb.DescribeDBInstancesOutput, error)
}

func init() {
	gob.Register([]docdbTypes.GlobalCluster{})
	//gob.Register([]docdbTypes.DBCluster{})
	//gob.Register([]docdbTypes.DBInstance{})

}

func CachedDocDBDescribeGlobalClusters(client DocDBClientInterface, accountID string, region string) ([]docdbTypes.GlobalCluster, error) {
	var PaginationControl *string
	var globalClusters []docdbTypes.GlobalCluster
	cacheKey := fmt.Sprintf("%s-docdb-DescribeGlobalClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "docdb:DescribeGlobalClusters",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]docdbTypes.GlobalCluster), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "docdb:DescribeGlobalClusters",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeGlobalClusters, err := client.DescribeGlobalClusters(
			context.TODO(),
			&docdb.DescribeGlobalClustersInput{
				Marker: PaginationControl,
			},
			func(o *docdb.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return globalClusters, err
		}

		globalClusters = append(globalClusters, DescribeGlobalClusters.GlobalClusters...)

		//pagination
		if DescribeGlobalClusters.Marker == nil {
			break
		}
		PaginationControl = DescribeGlobalClusters.Marker
	}

	internal.Cache.Set(cacheKey, globalClusters, cache.DefaultExpiration)
	return globalClusters, nil
}

func CachedDocDBDescribeDBClusters(client DocDBClientInterface, accountID string, region string) ([]docdbTypes.DBCluster, error) {
	var PaginationControl *string
	var dbClusters []docdbTypes.DBCluster
	cacheKey := fmt.Sprintf("%s-docdb-DescribeDBClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "docdb:DescribeDBClusters",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]docdbTypes.DBCluster), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "docdb:DescribeDBClusters",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeDBClusters, err := client.DescribeDBClusters(
			context.TODO(),
			&docdb.DescribeDBClustersInput{
				Marker: PaginationControl,
				Filters: []docdbTypes.Filter{
					{
						Name:   aws.String("engine"),
						Values: []string{"docdb"},
					},
				},
			},
			func(o *docdb.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return dbClusters, err
		}

		dbClusters = append(dbClusters, DescribeDBClusters.DBClusters...)

		//pagination
		if DescribeDBClusters.Marker == nil {
			break
		}
		PaginationControl = DescribeDBClusters.Marker
	}

	internal.Cache.Set(cacheKey, dbClusters, cache.DefaultExpiration)
	return dbClusters, nil
}

func CachedDocDBDescribeDBInstances(client DocDBClientInterface, accountID string, region string) ([]docdbTypes.DBInstance, error) {
	var PaginationControl *string
	var dbInstances []docdbTypes.DBInstance
	cacheKey := fmt.Sprintf("%s-docdb-DescribeDBInstances-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "docdb:DescribeDBInstances",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]docdbTypes.DBInstance), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "docdb:DescribeDBInstances",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeDBInstances, err := client.DescribeDBInstances(
			context.TODO(),
			&docdb.DescribeDBInstancesInput{
				Marker: PaginationControl,
			},
			func(o *docdb.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return dbInstances, err
		}

		dbInstances = append(dbInstances, DescribeDBInstances.DBInstances...)

		//pagination
		if DescribeDBInstances.Marker == nil {
			break
		}
		PaginationControl = DescribeDBInstances.Marker
	}

	internal.Cache.Set(cacheKey, dbInstances, cache.DefaultExpiration)
	return dbInstances, nil
}
