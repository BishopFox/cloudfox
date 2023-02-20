package aws

import (
	"context"
	"testing"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type MockedTagsGetResources struct {
}

func (m *MockedTagsGetResources) GetResources(ctx context.Context, params *resourcegroupstaggingapi.GetResourcesInput, optFns ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	testResources := []types.ResourceTagMapping{}
	testResources = append(testResources, types.ResourceTagMapping{
		ResourceARN: aws.String("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"),
		Tags: []types.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String("test"),
			},
		},
	})

	testGetResourcesOutput := &resourcegroupstaggingapi.GetResourcesOutput{
		ResourceTagMappingList: testResources,
	}

	return testGetResourcesOutput, nil
}

func TestTags(t *testing.T) {
	subtests := []struct {
		name            string
		outputDirectory string
		verbosity       int
		testModule      TagsModule
		expectedResult  []Tag
	}{
		{
			name:            "TestTags",
			outputDirectory: ".",
			verbosity:       2,
			testModule: TagsModule{
				ResourceGroupsTaggingApiInterface: &MockedTagsGetResources{},
				Caller: sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"),
					Arn:     aws.String("arn:aws:iam::123456789012:user/test"),
					UserId:  aws.String("AIDAJDPLRKLG7UEXAMPLE"),
				},
				AWSRegions:            []string{"us-east-1"},
				OutputFormat:          "table",
				Goroutines:            10,
				AWSProfile:            "test",
				WrapTable:             false,
				MaxResourcesPerRegion: 100,
			},
			expectedResult: []Tag{
				{
					AWSService: "ec2",
					Region:     "us-east-1",
					Type:       "instance",
					Key:        "Name",
					Value:      "test",
				},
			},
		},
	}
	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.PrintTags(subtest.testModule.OutputFormat, subtest.outputDirectory, subtest.verbosity)
			if len(subtest.testModule.Tags) != len(subtest.expectedResult) {
				t.Errorf("Expected %d results, got %d", len(subtest.expectedResult), len(subtest.testModule.Tags))
			}
			for i, ExpectedTag := range subtest.expectedResult {

				if ExpectedTag.Type != subtest.testModule.Tags[i].Type {
					t.Errorf("Expected Type = %s, got %s", subtest.testModule.Tags[i].Type, ExpectedTag.Type)
				}
				if ExpectedTag.Key != subtest.testModule.Tags[i].Key {
					t.Errorf("Expected Key = %s, got %s", subtest.testModule.Tags[i].Key, ExpectedTag.Key)
				}
				if ExpectedTag.Value != subtest.testModule.Tags[i].Value {
					t.Errorf("Expected Value = %s, got %s", subtest.testModule.Tags[i].Value, ExpectedTag.Value)
				}
			}
		})
	}

}
