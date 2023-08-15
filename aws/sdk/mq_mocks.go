package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqTypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
)

type MockedMQClient struct {
}

func (m *MockedMQClient) ListBrokers(ctx context.Context, input *mq.ListBrokersInput, options ...func(*mq.Options)) (*mq.ListBrokersOutput, error) {
	return &mq.ListBrokersOutput{
		BrokerSummaries: []mqTypes.BrokerSummary{
			{
				BrokerArn:        aws.String("broker1"),
				BrokerId:         aws.String("broker1"),
				BrokerName:       aws.String("broker1"),
				BrokerState:      mqTypes.BrokerStateRunning,
				Created:          aws.Time(time.Now()),
				DeploymentMode:   mqTypes.DeploymentModeSingleInstance,
				EngineType:       mqTypes.EngineTypeRabbitmq,
				HostInstanceType: aws.String("host1"),
			},
			{
				BrokerArn:        aws.String("broker2"),
				BrokerId:         aws.String("broker2"),
				BrokerName:       aws.String("broker2"),
				BrokerState:      mqTypes.BrokerStateRunning,
				Created:          aws.Time(time.Now()),
				DeploymentMode:   mqTypes.DeploymentModeSingleInstance,
				EngineType:       mqTypes.EngineTypeActivemq,
				HostInstanceType: aws.String("host2"),
			},
		},
	}, nil
}
