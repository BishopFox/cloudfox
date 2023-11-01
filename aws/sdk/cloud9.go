package sdk

import (
	"context"
	"encoding/gob"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/cloud9"
	cloud9Types "github.com/aws/aws-sdk-go-v2/service/cloud9/types"
	"github.com/patrickmn/go-cache"
)

type AWSCloud9ClientInterface interface {
	ListEnvironments(context.Context, *cloud9.ListEnvironmentsInput, ...func(*cloud9.Options)) (*cloud9.ListEnvironmentsOutput, error)
	DescribeEnvironments(context.Context, *cloud9.DescribeEnvironmentsInput, ...func(*cloud9.Options)) (*cloud9.DescribeEnvironmentsOutput, error)
}

func init() {
	gob.Register([]string{})
}

func CachedCloud9ListEnvironments(client AWSCloud9ClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var environments []string
	cacheKey := "cloud9-ListEnvironments-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]string), nil
	}
	for {
		ListEnvironments, err := client.ListEnvironments(
			context.TODO(),
			&cloud9.ListEnvironmentsInput{
				NextToken: PaginationControl,
			},
			func(o *cloud9.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return environments, err
		}

		environments = append(environments, ListEnvironments.EnvironmentIds...)

		//pagination
		if ListEnvironments.NextToken == nil {
			break
		}
		PaginationControl = ListEnvironments.NextToken
	}

	internal.Cache.Set(cacheKey, environments, cache.DefaultExpiration)
	return environments, nil
}

func CachedCloud9DescribeEnvironments(client AWSCloud9ClientInterface, accountID string, region string, environmentIDs []string) ([]cloud9Types.Environment, error) {
	var environments []cloud9Types.Environment
	cacheKey := "cloud9-DescribeEnvironments-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]cloud9Types.Environment), nil
	}
	for _, environmentID := range environmentIDs {
		DescribeEnvironments, err := client.DescribeEnvironments(
			context.TODO(),
			&cloud9.DescribeEnvironmentsInput{
				EnvironmentIds: []string{environmentID},
			},
			func(o *cloud9.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return environments, err
		}

		environments = append(environments, DescribeEnvironments.Environments...)

	}

	internal.Cache.Set(cacheKey, environments, cache.DefaultExpiration)
	return environments, nil
}
