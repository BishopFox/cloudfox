package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnerTypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
)

type MockedAppRunnerClient struct {
}

func (m *MockedAppRunnerClient) ListServices(ctx context.Context, input *apprunner.ListServicesInput, options ...func(*apprunner.Options)) (*apprunner.ListServicesOutput, error) {
	return &apprunner.ListServicesOutput{
		ServiceSummaryList: []apprunnerTypes.ServiceSummary{
			{
				ServiceName: aws.String("service1"),
			},
			{
				ServiceName: aws.String("service2"),
			},
		},
	}, nil
}
