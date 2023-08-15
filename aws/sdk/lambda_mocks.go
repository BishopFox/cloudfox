package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type MockedLambdaClient struct {
}

func (m *MockedLambdaClient) ListFunctions(ctx context.Context, input *lambda.ListFunctionsInput, options ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{
		Functions: []lambdaTypes.FunctionConfiguration{
			{
				FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
				FunctionName: aws.String("my-function"),
				Handler:      aws.String("index.handler"),
				Runtime:      lambdaTypes.RuntimeNodejs18x,
				Environment: &lambdaTypes.EnvironmentResponse{
					Variables: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
				},
			},
			{
				FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function2"),
				FunctionName: aws.String("my-function2"),
				Handler:      aws.String("index.handler"),
				Runtime:      lambdaTypes.RuntimeNodejs18x,
			},
		},
	}, nil
}

func (m *MockedLambdaClient) GetFunction(ctx context.Context, input *lambda.GetFunctionInput, options ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error) {
	return &lambda.GetFunctionOutput{
		Configuration: &lambdaTypes.FunctionConfiguration{
			FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
			FunctionName: aws.String("my-function"),
			Handler:      aws.String("index.handler"),
			Runtime:      lambdaTypes.RuntimeNodejs18x,
			Environment: &lambdaTypes.EnvironmentResponse{
				Variables: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
	}, nil
}

func (m *MockedLambdaClient) GetFunctionUrlConfig(ctx context.Context, input *lambda.GetFunctionInput, options ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error) {
	return &lambda.GetFunctionUrlConfigOutput{
		FunctionUrl: aws.String("https://my-function.us-east-1.amazonaws.com/Prod/"),
		FunctionArn: aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
		AuthType:    lambdaTypes.FunctionUrlAuthTypeNone,
	}, nil
}
