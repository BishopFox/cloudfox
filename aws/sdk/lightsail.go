package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailTypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
	"github.com/patrickmn/go-cache"
)

type lightsailClientInterface interface {
	GetInstances(context.Context, *lightsail.GetInstancesInput, ...func(*lightsail.Options)) (*lightsail.GetInstancesOutput, error)
	GetContainerServices(context.Context, *lightsail.GetContainerServicesInput, ...func(*lightsail.Options)) (*lightsail.GetContainerServicesOutput, error)
}

func init() {
	//gob.Register([]lightsailTypes.Instance{})
	gob.Register([]lightsailTypes.ContainerService{})

}

func CachedLightsailGetInstances(client lightsailClientInterface, accountID string, region string) ([]lightsailTypes.Instance, error) {
	var PaginationControl *string
	var services []lightsailTypes.Instance

	// TODO: When caching is enabled, this []lightsailTypes.Instance type clashes with the EC instance type when it comes to gob.Register. need to figure out how to register both types
	// cacheKey := fmt.Sprintf("%s-lightsail-GetInstances-%s", accountID, region)
	// cached, found := internal.Cache.Get(cacheKey)
	// if found {
	// 	return cached.([]lightsailTypes.Instance), nil
	// }
	for {
		GetInstances, err := client.GetInstances(
			context.TODO(),
			&lightsail.GetInstancesInput{
				PageToken: PaginationControl,
			},
			func(o *lightsail.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return services, err
		}

		services = append(services, GetInstances.Instances...)

		//pagination
		if GetInstances.NextPageToken == nil {
			break
		}
		PaginationControl = GetInstances.NextPageToken
	}

	// TODO: When caching is enabled, this []lightsailTypes.Instance type clashes with the EC instance type when it comes to gob.Register. need to figure out how to register both types
	//internal.Cache.Set(cacheKey, services, cache.DefaultExpiration)
	return services, nil
}

func CachedLightsailGetContainerServices(client lightsailClientInterface, accountID string, region string) ([]lightsailTypes.ContainerService, error) {
	var services []lightsailTypes.ContainerService
	cacheKey := fmt.Sprintf("%s-lightsail-GetContainerService-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]lightsailTypes.ContainerService), nil
	}
	GetInstances, err := client.GetContainerServices(
		context.TODO(),
		&lightsail.GetContainerServicesInput{},
		func(o *lightsail.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return services, err
	}

	services = append(services, GetInstances.ContainerServices...)

	internal.Cache.Set(cacheKey, services, cache.DefaultExpiration)
	return services, nil
}
