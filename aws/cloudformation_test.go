package aws

import (
	"context"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const DESCRIBE_STACKS_TEST_FILE = "./test-data/cloudformation-describestacks.json"
const TEMPLATE_BODY_TEST_FILE = "./test-data/cloudformation-getTemplate.json"

type Stacks struct {
	Stacks []struct {
		StackID           string            `json:"StackId"`
		Description       string            `json:"Description"`
		Tags              []interface{}     `json:"Tags"`
		Outputs           []types.Output    `json:"Outputs"`
		Parameters        []types.Parameter `json:"Parameters"`
		StackStatusReason interface{}       `json:"StackStatusReason"`
		CreationTime      time.Time         `json:"CreationTime"`
		Capabilities      []interface{}     `json:"Capabilities"`
		StackName         string            `json:"StackName"`
		RoleArn           string            `json:"RoleArn"`
		StackStatus       string            `json:"StackStatus"`
		DisableRollback   bool              `json:"DisableRollback"`
	} `json:"Stacks"`
}

type TemplateBody struct {
	TemplateBody string `json:"TemplateBody"`
}

type MockedCloudformationClientDescribeStacks struct {
	describeStacks Stacks
}

type MockedCloudformationClientGetTemplate struct {
	getTemplateBody TemplateBody
}

func (m *MockedCloudformationClientDescribeStacks) DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {

	err := json.Unmarshal(readTestFile(DESCRIBE_STACKS_TEST_FILE), &m.describeStacks)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_STACKS_TEST_FILE)
	}
	var stacks []types.Stack
	for _, stack := range m.describeStacks.Stacks {
		stacks = append(stacks, types.Stack{
			StackName:  &stack.StackName,
			RoleARN:    &stack.RoleArn,
			Outputs:    stack.Outputs,
			Parameters: stack.Parameters,
		})

	}

	return &cloudformation.DescribeStacksOutput{Stacks: stacks}, nil
}

func (m *MockedCloudformationClientGetTemplate) GetTemplate(ctx context.Context, params *cloudformation.GetTemplateInput, optFns ...func(*cloudformation.Options)) (*cloudformation.GetTemplateOutput, error) {
	err := json.Unmarshal(readTestFile(DESCRIBE_STACKS_TEST_FILE), &m.getTemplateBody)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", TEMPLATE_BODY_TEST_FILE)
	}

	return &cloudformation.GetTemplateOutput{TemplateBody: &m.getTemplateBody.TemplateBody}, nil
}

func TestCloudFormation(t *testing.T) {
	subtests := []struct {
		name            string
		outputDirectory string
		verbosity       int
		testModule      CloudformationModule
		expectedResult  []CFStack
	}{
		{
			name:            "test1",
			outputDirectory: ".",
			verbosity:       2,
			testModule: CloudformationModule{
				CloudFormationDescribeStacksInterface: &MockedCloudformationClientDescribeStacks{},
				CloudFormationGetTemplateInterface:    &MockedCloudformationClientGetTemplate{},
				Caller:                                sts.GetCallerIdentityOutput{Arn: aws.String("test")},
				OutputFormat:                          "table",
				AWSProfile:                            "test",
				Goroutines:                            30,
				AWSRegions:                            AWSRegions,
			},
			expectedResult: []CFStack{CFStack{
				Name: "myteststack",
				Role: "role123",
			}},
		},
	}
	utils.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.PrintCloudformationStacks(subtest.testModule.OutputFormat, subtest.outputDirectory, subtest.verbosity)
			for index, expectedStack := range subtest.expectedResult {
				if expectedStack.Name != subtest.testModule.CFStacks[index].Name {
					log.Fatal("Stack name does not match expected name")
				}
				if expectedStack.Role != subtest.testModule.CFStacks[index].Role {
					log.Fatal("Stack role does not match expected name")
				}

			}
		})
	}
}
