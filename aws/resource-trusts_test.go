package aws

import (
	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"testing"
)

func TestIsResourcePolicyInteresting(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "test1",
			input:    "Everyone can sqs:SendMessage & can sqs:ReceiveMessage",
			expected: true,
		},
		{
			name:     "PrincipalOrgPaths",
			input:    "aws:PrincipalOrgPaths",
			expected: true,
		},
		{
			name:     "Empty",
			input:    "",
			expected: false,
		},
		{
			name:     "NotInteresting",
			input:    "sns.amazonaws.com can lambda:InvokeFunction",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := isResourcePolicyInteresting(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected %v but got %v for input %s", tc.expected, actual, tc.input)
			}
		})
	}
}

func TestKMSResourceTrusts(t *testing.T) {
	testCases := []struct {
		outputDirectory string
		verbosity       int
		testModule      ResourceTrustsModule
		expectedResult  []Resource2
	}{
		{
			outputDirectory: ".",
			verbosity:       2,
			testModule: ResourceTrustsModule{
				KMSClient:  &sdk.MockedKMSClient{},
				AWSRegions: []string{"us-west-2"},
				Caller: sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"),
					Arn:     aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests"),
				},
				Goroutines: 30,
			},
			expectedResult: []Resource2{
				{
					Name: "key1",
					ARN:  "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
				},
			},
		},
	}

	for _, tc := range testCases {
		tc.testModule.PrintResources(tc.outputDirectory, tc.verbosity, true)
		for index, expectedResource2 := range tc.expectedResult {
			if expectedResource2.Name != tc.testModule.Resources2[index].Name {
				t.Fatal("Resource name does not match expected value")
			}
			if expectedResource2.ARN != tc.testModule.Resources2[index].ARN {
				t.Fatal("Resource ID does not match expected value")
			}
		}
	}
}
