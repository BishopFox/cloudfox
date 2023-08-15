package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfnTypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

type MockedStepFunctionsClient struct {
}

func (m *MockedStepFunctionsClient) ListStateMachines(ctx context.Context, input *sfn.ListStateMachinesInput, options ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
	return &sfn.ListStateMachinesOutput{
		StateMachines: []sfnTypes.StateMachineListItem{
			{
				Name:            aws.String("state_machine1"),
				StateMachineArn: aws.String("arn:aws:states:us-east-1:123456789012:stateMachine:state_machine1"),
			},
			{
				Name:            aws.String("state_machine2"),
				StateMachineArn: aws.String("arn:aws:states:us-east-1:123456789012:stateMachine:state_machine2"),
			},
		},
	}, nil
}
