package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbTypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/patrickmn/go-cache"
)

type ELBClientInterface interface {
	DescribeLoadBalancers(context.Context, *elasticloadbalancing.DescribeLoadBalancersInput, ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancersOutput, error)
}

func RegisterELBTypes() {
	gob.Register([]elbTypes.LoadBalancerDescription{})
}

func CachedELBDescribeLoadBalancers(client ELBClientInterface, accountID string, region string) ([]elbTypes.LoadBalancerDescription, error) {
	var PaginationControl *string
	var loadbalancers []elbTypes.LoadBalancerDescription
	cacheKey := fmt.Sprintf("%s-elb-DescribeLoadBalancers-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]elbTypes.LoadBalancerDescription), nil
	}
	for {
		DescribeLoadBalancers, err := client.DescribeLoadBalancers(
			context.TODO(),
			&elasticloadbalancing.DescribeLoadBalancersInput{
				Marker: PaginationControl,
			},
			func(o *elasticloadbalancing.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return loadbalancers, err
		}

		loadbalancers = append(loadbalancers, DescribeLoadBalancers.LoadBalancerDescriptions...)

		//pagination
		if DescribeLoadBalancers.NextMarker == nil {
			break
		}
		PaginationControl = DescribeLoadBalancers.NextMarker
	}

	internal.Cache.Set(cacheKey, loadbalancers, cache.DefaultExpiration)
	return loadbalancers, nil
}
