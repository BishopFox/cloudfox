package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagentTypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
)

type MockedBedrockAgentClient struct{}

func (m *MockedBedrockAgentClient) ListAgents(ctx context.Context, input *bedrockagent.ListAgentsInput, options ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error) {
	return &bedrockagent.ListAgentsOutput{
		AgentSummaries: []bedrockagentTypes.AgentSummary{
			{
				AgentId:            aws.String("AGENT001"),
				AgentName:          aws.String("LabAgent01"),
				AgentStatus:        bedrockagentTypes.AgentStatusPrepared,
				LatestAgentVersion: aws.String("1"),
			},
			{
				AgentId:            aws.String("AGENT002"),
				AgentName:          aws.String("ResearchWorker01"),
				AgentStatus:        bedrockagentTypes.AgentStatusPrepared,
				LatestAgentVersion: aws.String("1"),
			},
		},
	}, nil
}

func (m *MockedBedrockAgentClient) GetAgent(ctx context.Context, input *bedrockagent.GetAgentInput, options ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error) {
	agents := map[string]*bedrockagent.GetAgentOutput{
		"AGENT001": {
			Agent: &bedrockagentTypes.Agent{
				AgentId:              aws.String("AGENT001"),
				AgentName:            aws.String("LabAgent01"),
				AgentArn:             aws.String("arn:aws:bedrock:us-east-1:123456789012:agent/AGENT001"),
				AgentStatus:          bedrockagentTypes.AgentStatusPrepared,
				FoundationModel:      aws.String("us.anthropic.claude-sonnet-4-6"),
				AgentResourceRoleArn: aws.String("arn:aws:iam::123456789012:role/AgentExecutionRole-Lab"),
				Instruction:          aws.String("You are a helpful order management assistant."),
				IdleSessionTTLInSeconds: aws.Int32(600),
			},
		},
		"AGENT002": {
			Agent: &bedrockagentTypes.Agent{
				AgentId:              aws.String("AGENT002"),
				AgentName:            aws.String("ResearchWorker01"),
				AgentArn:             aws.String("arn:aws:bedrock:us-east-1:123456789012:agent/AGENT002"),
				AgentStatus:          bedrockagentTypes.AgentStatusPrepared,
				FoundationModel:      aws.String("us.anthropic.claude-sonnet-4-6"),
				AgentResourceRoleArn: aws.String("arn:aws:iam::123456789012:role/WorkerExecutionRole-Lab"),
				Instruction:          aws.String("You are a read-only research agent."),
				IdleSessionTTLInSeconds: aws.Int32(300),
			},
		},
	}
	if out, ok := agents[aws.ToString(input.AgentId)]; ok {
		return out, nil
	}
	return agents["AGENT001"], nil
}

func (m *MockedBedrockAgentClient) ListAgentAliases(ctx context.Context, input *bedrockagent.ListAgentAliasesInput, options ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentAliasesOutput, error) {
	return &bedrockagent.ListAgentAliasesOutput{
		AgentAliasSummaries: []bedrockagentTypes.AgentAliasSummary{
			{
				AgentAliasId:   aws.String("ALIAS001"),
				AgentAliasName: aws.String("lab-v1"),
			},
		},
	}, nil
}

func (m *MockedBedrockAgentClient) ListAgentActionGroups(ctx context.Context, input *bedrockagent.ListAgentActionGroupsInput, options ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentActionGroupsOutput, error) {
	return &bedrockagent.ListAgentActionGroupsOutput{
		ActionGroupSummaries: []bedrockagentTypes.ActionGroupSummary{
			{
				ActionGroupId:   aws.String("AG001"),
				ActionGroupName: aws.String("OrderLookupActionGroup"),
				ActionGroupState: bedrockagentTypes.ActionGroupStateEnabled,
			},
		},
	}, nil
}

func (m *MockedBedrockAgentClient) GetAgentActionGroup(ctx context.Context, input *bedrockagent.GetAgentActionGroupInput, options ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentActionGroupOutput, error) {
	return &bedrockagent.GetAgentActionGroupOutput{
		AgentActionGroup: &bedrockagentTypes.AgentActionGroup{
			ActionGroupId:    aws.String("AG001"),
			ActionGroupName:  aws.String("OrderLookupActionGroup"),
			ActionGroupState: bedrockagentTypes.ActionGroupStateEnabled,
			AgentId:          input.AgentId,
			AgentVersion:     input.AgentVersion,
			ActionGroupExecutor: &bedrockagentTypes.ActionGroupExecutorMemberLambda{
				Value: "arn:aws:lambda:us-east-1:123456789012:function:order_lookup_fn",
			},
			Description: aws.String("Looks up order status by order ID"),
			FunctionSchema: &bedrockagentTypes.FunctionSchemaMemberFunctions{
				Value: []bedrockagentTypes.Function{
					{
						Name:        aws.String("lookupOrder"),
						Description: aws.String("Look up an order by its ID"),
						Parameters: map[string]bedrockagentTypes.ParameterDetail{
							"orderId": {
								Type:        bedrockagentTypes.TypeString,
								Description: aws.String("The order identifier"),
								Required:    aws.Bool(true),
							},
						},
					},
				},
			},
		},
	}, nil
}

func (m *MockedBedrockAgentClient) ListAgentCollaborators(ctx context.Context, input *bedrockagent.ListAgentCollaboratorsInput, options ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentCollaboratorsOutput, error) {
	if aws.ToString(input.AgentId) == "AGENT001" {
		return &bedrockagent.ListAgentCollaboratorsOutput{
			AgentCollaboratorSummaries: []bedrockagentTypes.AgentCollaboratorSummary{
				{
					AgentDescriptor: &bedrockagentTypes.AgentDescriptor{
						AliasArn: aws.String("arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENT002/ALIAS002"),
					},
					CollaboratorId:   aws.String("COLLAB001"),
					CollaboratorName: aws.String("ResearchWorker01"),
					RelayConversationHistory: bedrockagentTypes.RelayConversationHistoryDisabled,
				},
			},
		}, nil
	}
	return &bedrockagent.ListAgentCollaboratorsOutput{
		AgentCollaboratorSummaries: []bedrockagentTypes.AgentCollaboratorSummary{},
	}, nil
}

func (m *MockedBedrockAgentClient) GetAgentCollaborator(ctx context.Context, input *bedrockagent.GetAgentCollaboratorInput, options ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentCollaboratorOutput, error) {
	return &bedrockagent.GetAgentCollaboratorOutput{
		AgentCollaborator: &bedrockagentTypes.AgentCollaborator{
			AgentDescriptor: &bedrockagentTypes.AgentDescriptor{
				AliasArn: aws.String("arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENT002/ALIAS002"),
			},
			CollaboratorId:           aws.String("COLLAB001"),
			CollaboratorName:         aws.String("ResearchWorker01"),
			CollaborationInstruction: aws.String("Route research and read-only queries to this worker"),
			RelayConversationHistory: bedrockagentTypes.RelayConversationHistoryDisabled,
		},
	}, nil
}
