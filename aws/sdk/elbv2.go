package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbV2Types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/patrickmn/go-cache"
)

type ELBv2ClientInterface interface {
	DescribeLoadBalancers(context.Context, *elasticloadbalancingv2.DescribeLoadBalancersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
}

func init() {
	gob.Register([]elbV2Types.LoadBalancer{})
}

func CachedELBv2DescribeLoadBalancers(client ELBv2ClientInterface, accountID string, region string) ([]elbV2Types.LoadBalancer, error) {
	var PaginationControl *string
	var loadbalancers []elbV2Types.LoadBalancer
	cacheKey := fmt.Sprintf("%s-elbv2-DescribeLoadBalancers-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]elbV2Types.LoadBalancer), nil
	}
	for {
		DescribeLoadBalancers, err := client.DescribeLoadBalancers(
			context.TODO(),
			&elasticloadbalancingv2.DescribeLoadBalancersInput{
				Marker: PaginationControl,
			},
			func(o *elasticloadbalancingv2.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return loadbalancers, err
		}

		loadbalancers = append(loadbalancers, DescribeLoadBalancers.LoadBalancers...)

		//pagination
		if DescribeLoadBalancers.NextMarker == nil {
			break
		}
		PaginationControl = DescribeLoadBalancers.NextMarker
	}

	internal.Cache.Set(cacheKey, loadbalancers, cache.DefaultExpiration)
	return loadbalancers, nil
}
