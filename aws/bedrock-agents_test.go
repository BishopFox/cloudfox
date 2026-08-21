package aws

import (
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestBedrockAgents(t *testing.T) {
	subtests := []struct {
		name            string
		outputDirectory string
		verbosity       int
		testModule      BedrockAgentsModule
		expectedResult  []BedrockAgent
	}{
		{
			name:            "test_bedrock_agents",
			outputDirectory: ".",
			verbosity:       2,
			testModule: BedrockAgentsModule{
				BedrockAgentClient: &sdk.MockedBedrockAgentClient{},
				Caller:             sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/test"), Account: aws.String("123456789012")},
				AWSProfile:         "test",
				Goroutines:         3,
				AWSRegions:         AWSRegions,
			},
			expectedResult: []BedrockAgent{
				{
					Name:            "LabAgent01",
					AgentId:         "AGENT001",
					Status:          "PREPARED",
					FoundationModel: "us.anthropic.claude-sonnet-4-6",
					ActionGroups:    1,
					Collaborators:   1,
				},
				{
					Name:            "ResearchWorker01",
					AgentId:         "AGENT002",
					Status:          "PREPARED",
					FoundationModel: "us.anthropic.claude-sonnet-4-6",
					ActionGroups:    1,
					Collaborators:   0,
				},
			},
		},
	}
	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.PrintBedrockAgents(subtest.outputDirectory, subtest.verbosity)
			for index, expectedAgent := range subtest.expectedResult {
				if index >= len(subtest.testModule.Agents) {
					log.Fatalf("Expected %d agents but only found %d", len(subtest.expectedResult), len(subtest.testModule.Agents))
				}
				if expectedAgent.Name != subtest.testModule.Agents[index].Name {
					log.Fatalf("Agent name %s does not match expected name %s", subtest.testModule.Agents[index].Name, expectedAgent.Name)
				}
				if expectedAgent.ActionGroups != subtest.testModule.Agents[index].ActionGroups {
					log.Fatalf("Agent %s action groups count %d does not match expected %d", expectedAgent.Name, subtest.testModule.Agents[index].ActionGroups, expectedAgent.ActionGroups)
				}
			}
		})
	}
}
