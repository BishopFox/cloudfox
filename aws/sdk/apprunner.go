package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnerTypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/patrickmn/go-cache"
)

type AppRunnerClientInterface interface {
	ListServices(context.Context, *apprunner.ListServicesInput, ...func(*apprunner.Options)) (*apprunner.ListServicesOutput, error)
}

func RegisterApprunnerTypes() {
	gob.Register([]apprunnerTypes.Service{})
	gob.Register([]apprunnerTypes.ServiceSummary{})
}

func CachedAppRunnerListServices(client AppRunnerClientInterface, accountID string, region string) ([]apprunnerTypes.ServiceSummary, error) {
	var PaginationControl *string
	var services []apprunnerTypes.ServiceSummary
	cacheKey := fmt.Sprintf("%s-apprunner-ListServices-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]apprunnerTypes.ServiceSummary), nil
	}
	for {
		ListServices, err := client.ListServices(
			context.TODO(),
			&apprunner.ListServicesInput{
				NextToken: PaginationControl,
			},
			func(o *apprunner.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return services, err
		}

		services = append(services, ListServices.ServiceSummaryList...)

		//pagination
		if ListServices.NextToken == nil {
			break
		}
		PaginationControl = ListServices.NextToken
	}

	internal.Cache.Set(cacheKey, services, cache.DefaultExpiration)
	return services, nil
}
