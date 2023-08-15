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
				Id:   aws.String("api1"),
				Name: aws.String("api1"),
			},
			{
				Id:   aws.String("api2"),
				Name: aws.String("api2"),
			},
		},
	}, nil
}
