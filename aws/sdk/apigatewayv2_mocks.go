package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apiGatwayV2Types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

type MockedAWSAPIGatewayv2Client struct {
}

func (m *MockedAWSAPIGatewayv2Client) GetApis(ctx context.Context, input *apigatewayv2.GetApisInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	return &apigatewayv2.GetApisOutput{
		Items: []apiGatwayV2Types.Api{
			{
				ApiId:       aws.String("asdfsdfasdf"),
				Name:        aws.String("api1"),
				ApiEndpoint: aws.String("https://asdfsdfasdf.execute-api.us-east-1.amazonaws.com"),
			},
			{
				ApiId:       aws.String("qwertyqwerty"),
				Name:        aws.String("api2"),
				ApiEndpoint: aws.String("https://qwertyqwerty.execute-api.us-east-1.amazonaws.com"),
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayv2Client) GetDomainNames(ctx context.Context, input *apigatewayv2.GetDomainNamesInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error) {
	return &apigatewayv2.GetDomainNamesOutput{
		Items: []apiGatwayV2Types.DomainName{
			{
				DomainName: aws.String("domain1"),
			},
			{
				DomainName: aws.String("domain2"),
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayv2Client) GetApiMappings(ctx context.Context, input *apigatewayv2.GetApiMappingsInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApiMappingsOutput, error) {
	return &apigatewayv2.GetApiMappingsOutput{
		Items: []apiGatwayV2Types.ApiMapping{
			{
				ApiMappingId: aws.String("apiMapping1"),
			},
			{
				ApiMappingId: aws.String("apiMapping2"),
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayv2Client) GetStages(ctx context.Context, input *apigatewayv2.GetStagesInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error) {
	return &apigatewayv2.GetStagesOutput{
		Items: []apiGatwayV2Types.Stage{
			{
				StageName: aws.String("stage1"),
			},
			{
				StageName: aws.String("stage2"),
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayv2Client) GetRoutes(ctx context.Context, input *apigatewayv2.GetRoutesInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error) {
	return &apigatewayv2.GetRoutesOutput{
		Items: []apiGatwayV2Types.Route{
			{
				RouteId:  aws.String("route1"),
				RouteKey: aws.String("POST /route1"),
			},
			{
				RouteId:  aws.String("route2"),
				RouteKey: aws.String("GET /route2"),
			},
		},
	}, nil
}
