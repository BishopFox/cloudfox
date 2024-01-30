package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloud9"
	"github.com/aws/aws-sdk-go-v2/service/cloud9/types"
)

type MockedAWSCloud9Client struct {
}

func (m *MockedAWSCloud9Client) ListEnvironments(ctx context.Context, input *cloud9.ListEnvironmentsInput, options ...func(*cloud9.Options)) (*cloud9.ListEnvironmentsOutput, error) {
	return &cloud9.ListEnvironmentsOutput{
		EnvironmentIds: []string{
			"env1",
			"env2",
		},
	}, nil
}

func (m *MockedAWSCloud9Client) DescribeEnvironments(ctx context.Context, input *cloud9.DescribeEnvironmentsInput, options ...func(*cloud9.Options)) (*cloud9.DescribeEnvironmentsOutput, error) {
	return &cloud9.DescribeEnvironmentsOutput{
		Environments: []types.Environment{
			{
				Name: aws.String("env1"),
				Arn:  aws.String("arn:aws:cloud9:us-east-1:123456789012:environment/env1"),
			},
			{
				Name: aws.String("env2"),
				Arn:  aws.String("arn:aws:cloud9:us-east-1:123456789012:environment/env2"),
			},
		},
	}, nil
}
