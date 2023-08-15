package aws

import (
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

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
				CloudFormationClient: &sdk.MockedCloudformationClient{},
				Caller:               sts.GetCallerIdentityOutput{Arn: aws.String("test")},
				OutputFormat:         "table",
				AWSProfile:           "test",
				Goroutines:           30,
				AWSRegions:           AWSRegions,
			},
			expectedResult: []CFStack{{
				Name: "myteststack",
				Role: "role123",
			}},
		},
	}
	internal.MockFileSystem(true)
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
