package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apiGatewayTypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
)

type APIGatewayClientInterface interface {
	GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error)
}

func RegisterApiGatewayTypes() {
	gob.Register([]apiGatewayTypes.RestApi{})
}

// create a CachedApiGatewayGetRestAPIs function that accepts a client, account id, region. Make sure it handles caching, the region option and pagination
func CachedApiGatewayGetRestAPIs(client APIGatewayClientInterface, accountID string, region string) ([]apiGatewayTypes.RestApi, error) {
	var PaginationControl *string
	var restAPIs []apiGatewayTypes.RestApi
	cacheKey := fmt.Sprintf("%s-apigateway-GetRestApis-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]apiGatewayTypes.RestApi), nil
	}

	for {
		GetRestApis, err := client.GetRestApis(
			context.TODO(),
			&apigateway.GetRestApisInput{
				Position: PaginationControl,
			},
			func(o *apigateway.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return restAPIs, err
		}

		restAPIs = append(restAPIs, GetRestApis.Items...)

		//pagination
		if GetRestApis.Position == nil {
			break
		}
		PaginationControl = GetRestApis.Position
	}

	return restAPIs, nil
}
