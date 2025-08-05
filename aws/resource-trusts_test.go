package aws

import (
	"testing"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	mockedKMSClient := &sdk.MockedKMSClient{}
	var kmsClient sdk.KMSClientInterface = mockedKMSClient

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
				KMSClient:        &kmsClient,
				APIGatewayClient: nil,
				EC2Client:        nil,
				AWSRegions:       []string{"us-west-2"},
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
				t.Fatal("Resource ARN does not match expected value")
			}
		}
	}
}

func TestAPIGatewayResourceTrusts(t *testing.T) {

	mockedAPIGatewayClient := &sdk.MockedAWSAPIGatewayClient{}
	var apiGatewayClient sdk.APIGatewayClientInterface = mockedAPIGatewayClient

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
				KMSClient:        nil,
				APIGatewayClient: &apiGatewayClient,
				EC2Client:        nil,
				AWSRegions:       []string{"us-west-2"},
				Caller: sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"),
					Arn:     aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests"),
				},
				Goroutines: 30,
			},
			expectedResult: []Resource2{
				{
					Name:        "api1",
					ARN:         "arn:aws:execute-api:us-west-2:123456789012:abcdefg/*",
					Public:      "No",
					Interesting: "Yes",
				},
			},
		},
	}

	for _, tc := range testCases {
		tc.testModule.PrintResources(tc.outputDirectory, tc.verbosity, false)
		for index, expectedResource2 := range tc.expectedResult {
			if expectedResource2.Name != tc.testModule.Resources2[index].Name {
				t.Fatal("Resource name does not match expected value")
			}
			if expectedResource2.ARN != tc.testModule.Resources2[index].ARN {
				t.Fatal("Resource ARN does not match expected value")
			}
			if expectedResource2.Public != tc.testModule.Resources2[index].Public {
				t.Fatal("Resource Public does not match expected value")
			}
			if expectedResource2.Interesting != tc.testModule.Resources2[index].Interesting {
				t.Fatal("Resource Interesting does not match expected value")
			}
		}
	}
}

func TestVpcEndpointResourceTrusts(t *testing.T) {

	mockedEC2Client := &sdk.MockedEC2Client2{}
	var ec2Client sdk.AWSEC2ClientInterface = mockedEC2Client

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
				KMSClient:        nil,
				APIGatewayClient: nil,
				EC2Client:        &ec2Client,
				AWSRegions:       []string{"us-west-2"},
				Caller: sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"),
					Arn:     aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests"),
				},
				Goroutines: 30,
			},
			expectedResult: []Resource2{
				{
					Name:   "vpce-1234567890abcdefg",
					ARN:    "vpce-1234567890abcdefg",
					Public: "No",
				},
				{
					Name:   "vpce-1234567890abcdefh",
					ARN:    "vpce-1234567890abcdefh",
					Public: "No",
				},
			},
		},
	}

	for _, tc := range testCases {
		tc.testModule.PrintResources(tc.outputDirectory, tc.verbosity, false)
		for index, expectedResource2 := range tc.expectedResult {
			if expectedResource2.Name != tc.testModule.Resources2[index].Name {
				t.Fatal("Resource name does not match expected value")
			}
			if expectedResource2.ARN != tc.testModule.Resources2[index].ARN {
				t.Fatal("Resource ARN does not match expected value")
			}
			if expectedResource2.Public != tc.testModule.Resources2[index].Public {
				t.Fatal("Resource Public does not match expected value")
			}
		}
	}
}

func TestOpenSearchResourceTrusts(t *testing.T) {

	mockedOpenSearchClient := &sdk.MockedOpenSearchClient{}
	var openSearchClient sdk.OpenSearchClientInterface = mockedOpenSearchClient

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
				KMSClient:        nil,
				APIGatewayClient: nil,
				EC2Client:        nil,
				OpenSearchClient: &openSearchClient,
				AWSRegions:       []string{"us-west-2"},
				Caller: sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"),
					Arn:     aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests"),
				},
				Goroutines: 30,
			},
			expectedResult: []Resource2{
				{
					Name:   "domain1",
					ARN:    "arn:aws:es:us-east-1:123456789012:domain/domain1",
					Public: "No",
				},
				{
					Name:   "domain2",
					ARN:    "arn:aws:es:us-east-1:123456789012:domain/domain2",
					Public: "Yes",
				},
			},
		},
	}

	for _, tc := range testCases {
		tc.testModule.PrintResources(tc.outputDirectory, tc.verbosity, false)
		for index, expectedResource2 := range tc.expectedResult {
			if expectedResource2.Name != tc.testModule.Resources2[index].Name {
				t.Fatal("Resource name does not match expected value")
			}
			if expectedResource2.ARN != tc.testModule.Resources2[index].ARN {
				t.Fatal("Resource ARN does not match expected value")
			}
			if expectedResource2.Public != tc.testModule.Resources2[index].Public {
				t.Fatal("Resource Public does not match expected value")
			}
		}
	}
}
