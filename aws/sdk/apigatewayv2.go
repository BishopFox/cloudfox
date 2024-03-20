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
	GetDomainNames(context.Context, *apigatewayv2.GetDomainNamesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error)
	GetApiMappings(context.Context, *apigatewayv2.GetApiMappingsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApiMappingsOutput, error)
	GetStages(context.Context, *apigatewayv2.GetStagesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error)
	GetRoutes(context.Context, *apigatewayv2.GetRoutesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error)
}

type domainName apiGatwayV2Types.DomainName
type stage apiGatwayV2Types.Stage

func init() {
	gob.Register([]apiGatwayV2Types.Api{})
	//need to do this to avoid conflicts with the Instance type in the ec2 package
	gob.Register([]domainName{})
	gob.Register([]apiGatwayV2Types.ApiMapping{})
	gob.Register([]stage{})
	gob.Register([]apiGatwayV2Types.Route{})
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

func CachedAPIGatewayv2GetDomainNames(client APIGatewayv2ClientInterface, accountID string, region string) ([]domainName, error) {
	var PaginationControl *string
	var domainNames []domainName
	cacheKey := fmt.Sprintf("%s-apigatewayv2-GetDomainNames-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]domainName), nil
	}
	for {
		GetDomainNames, err := client.GetDomainNames(
			context.TODO(),
			&apigatewayv2.GetDomainNamesInput{
				NextToken: PaginationControl,
			},
			func(o *apigatewayv2.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return domainNames, err
		}
		// convert []apiGatwayV2Types.DomainName to []domainName

		// Convert each element to domainName before appending to avoid conflicting with apigateway's domainname type
		for _, item := range GetDomainNames.Items {
			domainNames = append(domainNames, domainName(item))
		}

		//pagination
		if GetDomainNames.NextToken == nil {
			break
		}
		PaginationControl = GetDomainNames.NextToken
	}

	internal.Cache.Set(cacheKey, domainNames, cache.DefaultExpiration)
	return domainNames, nil
}

func CachedAPIGatewayv2GetApiMappings(client APIGatewayv2ClientInterface, accountID string, region string, domain string) ([]apiGatwayV2Types.ApiMapping, error) {
	var PaginationControl *string
	var apiMappings []apiGatwayV2Types.ApiMapping
	cacheKey := fmt.Sprintf("%s-apigatewayv2-GetApiMappings-%s-%s", accountID, region, domain)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]apiGatwayV2Types.ApiMapping), nil
	}
	for {
		GetApiMappings, err := client.GetApiMappings(
			context.TODO(),
			&apigatewayv2.GetApiMappingsInput{
				DomainName: &domain,
				NextToken:  PaginationControl,
			},
			func(o *apigatewayv2.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return apiMappings, err
		}

		apiMappings = append(apiMappings, GetApiMappings.Items...)

		//pagination
		if GetApiMappings.NextToken == nil {
			break
		}
		PaginationControl = GetApiMappings.NextToken
	}

	internal.Cache.Set(cacheKey, apiMappings, cache.DefaultExpiration)
	return apiMappings, nil
}

func CachedAPIGatewayv2GetStages(client APIGatewayv2ClientInterface, accountID string, region string, apiID string) ([]apiGatwayV2Types.Stage, error) {
	var PaginationControl *string
	var stages []apiGatwayV2Types.Stage
	cacheKey := fmt.Sprintf("%s-apigatewayv2-GetStages-%s-%s", accountID, region, apiID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]apiGatwayV2Types.Stage), nil
	}
	for {
		GetStages, err := client.GetStages(
			context.TODO(),
			&apigatewayv2.GetStagesInput{
				ApiId:     &apiID,
				NextToken: PaginationControl,
			},
			func(o *apigatewayv2.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return stages, err
		}

		stages = append(stages, GetStages.Items...)

		//pagination
		if GetStages.NextToken == nil {
			break
		}
		PaginationControl = GetStages.NextToken
	}

	internal.Cache.Set(cacheKey, stages, cache.DefaultExpiration)
	return stages, nil
}

func CachedAPIGatewayv2GetRoutes(client APIGatewayv2ClientInterface, accountID string, region string, apiID string) ([]apiGatwayV2Types.Route, error) {
	var PaginationControl *string
	var routes []apiGatwayV2Types.Route
	cacheKey := fmt.Sprintf("%s-apigatewayv2-GetRoutes-%s-%s", accountID, region, apiID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]apiGatwayV2Types.Route), nil
	}
	for {
		GetRoutes, err := client.GetRoutes(
			context.TODO(),
			&apigatewayv2.GetRoutesInput{
				ApiId:     &apiID,
				NextToken: PaginationControl,
			},
			func(o *apigatewayv2.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return routes, err
		}

		routes = append(routes, GetRoutes.Items...)

		//pagination
		if GetRoutes.NextToken == nil {
			break
		}
		PaginationControl = GetRoutes.NextToken
	}

	internal.Cache.Set(cacheKey, routes, cache.DefaultExpiration)
	return routes, nil
}
