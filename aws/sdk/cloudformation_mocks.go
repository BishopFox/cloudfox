package sdk

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
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

type MockedCloudformationClient struct {
	describeStacks  Stacks
	getTemplateBody TemplateBody
}

func (m *MockedCloudformationClient) DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {

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

func (m *MockedCloudformationClient) GetTemplate(ctx context.Context, params *cloudformation.GetTemplateInput, optFns ...func(*cloudformation.Options)) (*cloudformation.GetTemplateOutput, error) {
	err := json.Unmarshal(readTestFile(DESCRIBE_STACKS_TEST_FILE), &m.getTemplateBody)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", TEMPLATE_BODY_TEST_FILE)
	}

	return &cloudformation.GetTemplateOutput{TemplateBody: &m.getTemplateBody.TemplateBody}, nil
}

func (m *MockedCloudformationClient) ListStacks(ctx context.Context, params *cloudformation.ListStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error) {
	return &cloudformation.ListStacksOutput{}, nil
}
