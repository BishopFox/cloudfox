package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	eksTypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/patrickmn/go-cache"
)

type EKSClientInterface interface {
	DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
}

func RegisterEKSTypes() {
	gob.Register([]string{})
	gob.Register(eksTypes.Cluster{})
}

func CachedEKSDescribeCluster(client EKSClientInterface, accountID string, region string, clusterName string) (eksTypes.Cluster, error) {
	var cluster eksTypes.Cluster
	cacheKey := fmt.Sprintf("%s-eks-DescribeCluster-%s-%s", accountID, region, clusterName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(eksTypes.Cluster), nil
	}
	clusterOutput, err := client.DescribeCluster(
		context.TODO(),
		&eks.DescribeClusterInput{
			Name: &clusterName,
		},
		func(o *eks.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return cluster, err
	}
	cluster = *clusterOutput.Cluster

	internal.Cache.Set(cacheKey, cluster, cache.DefaultExpiration)
	return cluster, nil
}

func CachedEKSListClusters(client EKSClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var clusters []string
	cacheKey := fmt.Sprintf("%s-eks-ListClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]string), nil
	}
	for {
		ListClusters, err := client.ListClusters(
			context.TODO(),
			&eks.ListClustersInput{
				NextToken: PaginationControl,
			},
			func(o *eks.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return clusters, err
		}

		clusters = append(clusters, ListClusters.Clusters...)

		//pagination
		if ListClusters.NextToken == nil {
			break
		}
		PaginationControl = ListClusters.NextToken
	}

	internal.Cache.Set(cacheKey, clusters, cache.DefaultExpiration)
	return clusters, nil
}
