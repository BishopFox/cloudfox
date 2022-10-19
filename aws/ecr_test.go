package aws

import (
	"context"
	"testing"

	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var AWSRegions = []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-3", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-west-3", "eu-north-1", "me-south-1", "sa-east-1"}

type MockedECRClient struct {
}

func (m *MockedECRClient) DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return &ecr.DescribeRepositoriesOutput{}, nil
}

func TestDescribeRepos(t *testing.T) {
	subtests := []struct {
		name            string
		outputFormat    string
		outputDirectory string
		verbosity       int
		mockedModule    ECRModule
	}{
		{
			name:            "subtest 1: using mocked ECR client",
			outputFormat:    "table",
			outputDirectory: ".",
			verbosity:       1,
			mockedModule: ECRModule{
				ECRClientM: &MockedECRClient{},
				Caller: sts.GetCallerIdentityOutput{
					Arn: aws.String("arn:aws:iam::123456789012:user/subtest1"),
				},
				AWSRegions: AWSRegions,
				AWSProfile: "default",
				Goroutines: 30,
			},
		},
		{
			name:            "subtest 2: using production ECR client",
			outputFormat:    "table",
			outputDirectory: ".",
			verbosity:       1,
			mockedModule: ECRModule{
				ECRClientM: &ecr.Client{},
				Caller: sts.GetCallerIdentityOutput{
					Arn: aws.String("arn:aws:iam::123456789012:user/subtest2"),
				},
				AWSRegions: AWSRegions,
				AWSProfile: "default",
				Goroutines: 30,
			},
		},
	}
	utils.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.mockedModule.DescribeReposDONOTUSE()
		})
	}
}
