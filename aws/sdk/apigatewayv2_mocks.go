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
				ApiId: aws.String("api1"),
				Name:  aws.String("api1"),
			},
			{
				ApiId: aws.String("api2"),
				Name:  aws.String("api2"),
			},
		},
	}, nil
}
