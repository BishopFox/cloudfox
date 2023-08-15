package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/patrickmn/go-cache"
)

type AWSRoute53ClientInterface interface {
	ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

func init() {
	gob.Register([]route53types.HostedZone{})
	gob.Register([]route53types.ResourceRecordSet{})

}

func CachedRoute53ListHostedZones(client AWSRoute53ClientInterface, accountID string) ([]route53types.HostedZone, error) {
	var PaginationControl *string
	var hostedZones []route53types.HostedZone
	cacheKey := fmt.Sprintf("%s-route53-ListHostedZones", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]route53types.HostedZone), nil
	}

	for {
		ListHostedZones, err := client.ListHostedZones(
			context.TODO(),
			&route53.ListHostedZonesInput{
				Marker: PaginationControl,
			},
		)

		if err != nil {
			return hostedZones, err
		}

		hostedZones = append(hostedZones, ListHostedZones.HostedZones...)

		//pagination
		if ListHostedZones.Marker == nil {
			break
		}
		PaginationControl = ListHostedZones.Marker
	}
	internal.Cache.Set(cacheKey, hostedZones, cache.DefaultExpiration)
	return hostedZones, nil
}

func CachedRoute53ListResourceRecordSets(client AWSRoute53ClientInterface, accountID string, hostedZoneID string) ([]route53types.ResourceRecordSet, error) {
	var PaginationControl *string
	var resourceRecordSets []route53types.ResourceRecordSet
	// remove the /hostedzone/ prefix
	hostedZoneID = hostedZoneID[12:]
	cacheKey := fmt.Sprintf("%s-route53-ListResourceRecordSets-%s", accountID, hostedZoneID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]route53types.ResourceRecordSet), nil
	}

	for {
		ListResourceRecordSets, err := client.ListResourceRecordSets(
			context.TODO(),
			&route53.ListResourceRecordSetsInput{
				HostedZoneId:    &hostedZoneID,
				StartRecordName: PaginationControl,
			},
		)

		if err != nil {
			return resourceRecordSets, err
		}

		resourceRecordSets = append(resourceRecordSets, ListResourceRecordSets.ResourceRecordSets...)

		//pagination
		if !ListResourceRecordSets.IsTruncated {
			break
		}
		PaginationControl = ListResourceRecordSets.NextRecordName
	}
	internal.Cache.Set(cacheKey, resourceRecordSets, cache.DefaultExpiration)
	return resourceRecordSets, nil
}
