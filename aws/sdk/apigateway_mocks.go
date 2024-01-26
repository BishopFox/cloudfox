package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apiGatewayTypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
)

type MockedAWSAPIGatewayClient struct {
}

func (m *MockedAWSAPIGatewayClient) GetRestApis(ctx context.Context, input *apigateway.GetRestApisInput, options ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	return &apigateway.GetRestApisOutput{
		Items: []apiGatewayTypes.RestApi{
			{
				Id:   aws.String("abcdefg"),
				Name: aws.String("api1"),
				EndpointConfiguration: &apiGatewayTypes.EndpointConfiguration{
					Types: []apiGatewayTypes.EndpointType{
						apiGatewayTypes.EndpointTypePrivate,
					},
				},
			},
			{
				Id:   aws.String("qwerty"),
				Name: aws.String("api2"),
				EndpointConfiguration: &apiGatewayTypes.EndpointConfiguration{
					Types: []apiGatewayTypes.EndpointType{
						apiGatewayTypes.EndpointTypeRegional,
					},
				},
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayClient) GetStages(ctx context.Context, input *apigateway.GetStagesInput, options ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
	return &apigateway.GetStagesOutput{
		Item: []apiGatewayTypes.Stage{
			{
				StageName: aws.String("stage1"),
			},
			{
				StageName: aws.String("stage2"),
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayClient) GetResources(ctx context.Context, input *apigateway.GetResourcesInput, options ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	return &apigateway.GetResourcesOutput{
		Items: []apiGatewayTypes.Resource{
			{
				Id:   aws.String("resource1"),
				Path: aws.String("/path1"),
				ResourceMethods: map[string]apiGatewayTypes.Method{
					"GET": {
						ApiKeyRequired: aws.Bool(true),
						AuthorizerId:   aws.String("authorizer1"),
						OperationName:  aws.String("operation1"),
					},
				},
			},
			{
				Id:   aws.String("resource2"),
				Path: aws.String("/path2"),
				ResourceMethods: map[string]apiGatewayTypes.Method{
					"ANY": {
						ApiKeyRequired: aws.Bool(true),
						AuthorizerId:   aws.String("authorizer2"),
						OperationName:  aws.String("operation2"),
					},
				},
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayClient) GetDomainNames(ctx context.Context, input *apigateway.GetDomainNamesInput, options ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	return &apigateway.GetDomainNamesOutput{
		Items: []apiGatewayTypes.DomainName{},
	}, nil
}

func (m *MockedAWSAPIGatewayClient) GetBasePathMappings(ctx context.Context, input *apigateway.GetBasePathMappingsInput, options ...func(*apigateway.Options)) (*apigateway.GetBasePathMappingsOutput, error) {
	return &apigateway.GetBasePathMappingsOutput{
		Items: []apiGatewayTypes.BasePathMapping{
			{
				BasePath:  aws.String("basepath1"),
				RestApiId: aws.String("abcdefg"),
				Stage:     aws.String("stage1"),
			},
			{
				BasePath:  aws.String("basepath2"),
				RestApiId: aws.String("qwerty"),
				Stage:     aws.String("stage2"),
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayClient) GetMethod(ctx context.Context, input *apigateway.GetMethodInput, options ...func(*apigateway.Options)) (*apigateway.GetMethodOutput, error) {
	return &apigateway.GetMethodOutput{
		ApiKeyRequired: aws.Bool(true),
	}, nil
}

func (m *MockedAWSAPIGatewayClient) GetUsagePlans(ctx context.Context, input *apigateway.GetUsagePlansInput, options ...func(*apigateway.Options)) (*apigateway.GetUsagePlansOutput, error) {
	return &apigateway.GetUsagePlansOutput{
		Items: []apiGatewayTypes.UsagePlan{
			{
				Id:   aws.String("usageplan1"),
				Name: aws.String("usageplan1"),
				ApiStages: []apiGatewayTypes.ApiStage{
					{
						ApiId: aws.String("abcdefg"),
						Stage: aws.String("stage2"),
					},
				},
			},
		},
	}, nil
}

func (m *MockedAWSAPIGatewayClient) GetUsagePlanKeys(ctx context.Context, input *apigateway.GetUsagePlanKeysInput, options ...func(*apigateway.Options)) (*apigateway.GetUsagePlanKeysOutput, error) {
	return &apigateway.GetUsagePlanKeysOutput{
		Items: []apiGatewayTypes.UsagePlanKey{
			{
				Id:    aws.String("usageplankey1"),
				Type:  aws.String("API_KEY"),
				Value: aws.String("23oieuwefo3rfs"),
			},
			{
				Id:    aws.String("usageplankey2"),
				Type:  aws.String("API_KEY"),
				Value: aws.String("982yf98fdv8dlds"),
			},
		},
	}, nil
}
