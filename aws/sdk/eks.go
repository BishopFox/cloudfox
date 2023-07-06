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
	DescribeNodegroup(context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error)
	ListNodegroups(context.Context, *eks.ListNodegroupsInput, ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error)
}

func init() {
	gob.Register([]string{})
	gob.Register(eksTypes.Cluster{})
	gob.Register(eksTypes.Nodegroup{})

}

func CachedEKSDescribeCluster(client EKSClientInterface, accountID string, clusterName string, region string) (eksTypes.Cluster, error) {
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

func CachedEKSListNodeGroups(client EKSClientInterface, accountID string, region string, clusterName string) ([]string, error) {
	var PaginationControl *string
	var nodeGroups []string
	cacheKey := fmt.Sprintf("%s-eks-ListNodeGroups-%s-%s", accountID, region, clusterName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]string), nil
	}
	for {
		ListNodeGroups, err := client.ListNodegroups(
			context.TODO(),
			&eks.ListNodegroupsInput{
				ClusterName: &clusterName,
				NextToken:   PaginationControl,
			},
			func(o *eks.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return nodeGroups, err
		}

		nodeGroups = append(nodeGroups, ListNodeGroups.Nodegroups...)
		if ListNodeGroups.NextToken != nil {
			PaginationControl = ListNodeGroups.NextToken
		} else {
			PaginationControl = nil
			break
		}

	}
	internal.Cache.Set(cacheKey, nodeGroups, cache.DefaultExpiration)

	return nodeGroups, nil
}

func CachedEKSDescribeNodeGroup(client EKSClientInterface, accountID string, region string, clusterName string, nodeGroupName string) (eksTypes.Nodegroup, error) {
	var nodeGroup eksTypes.Nodegroup
	cacheKey := fmt.Sprintf("%s-eks-DescribeNodeGroup-%s-%s-%s", accountID, region, nodeGroupName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(eksTypes.Nodegroup), nil
	}
	nodeGroupOutput, err := client.DescribeNodegroup(
		context.TODO(),
		&eks.DescribeNodegroupInput{
			ClusterName:   &clusterName,
			NodegroupName: &nodeGroupName,
		},
		func(o *eks.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return nodeGroup, err
	}
	nodeGroup = *nodeGroupOutput.Nodegroup

	internal.Cache.Set(cacheKey, nodeGroup, cache.DefaultExpiration)
	return nodeGroup, nil
}
