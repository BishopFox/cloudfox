package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apiGatwayV2Types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"

	"github.com/patrickmn/go-cache"
)

type APIGatewayv2ClientInterface interface {
	GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error)
}

func RegisterApiGatewayV2Types() {
	gob.Register([]apiGatwayV2Types.Api{})
}

func CachedAPIGatewayv2GetAPIs(client APIGatewayv2ClientInterface, accountID string, region string) ([]apiGatwayV2Types.Api, error) {
	var PaginationControl *string
	var apis []apiGatwayV2Types.Api
	cacheKey := fmt.Sprintf("%s-apigatewayv2-GetApis-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]apiGatwayV2Types.Api), nil
	}
	for {
		GetApis, err := client.GetApis(
			context.TODO(),
			&apigatewayv2.GetApisInput{
				NextToken: PaginationControl,
			},
			func(o *apigatewayv2.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return apis, err
		}

		apis = append(apis, GetApis.Items...)

		//pagination
		if GetApis.NextToken == nil {
			break
		}
		PaginationControl = GetApis.NextToken
	}

	internal.Cache.Set(cacheKey, apis, cache.DefaultExpiration)
	return apis, nil
}
