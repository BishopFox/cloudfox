package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type MockedSSMClient struct {
}

func (m *MockedSSMClient) DescribeParameters(ctx context.Context, input *ssm.DescribeParametersInput, options ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	return &ssm.DescribeParametersOutput{
		Parameters: []ssmTypes.ParameterMetadata{
			{
				Name: aws.String("/parameter/param1"),
				Type: ssmTypes.ParameterTypeString,
			},
			{
				Name: aws.String("/parameter/param2"),
				Type: ssmTypes.ParameterTypeString,
			},
		},
	}, nil
}
