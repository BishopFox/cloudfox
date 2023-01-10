package aws

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var AWSRegions = []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-3", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-west-3", "eu-north-1", "me-south-1", "sa-east-1"}

type MockedECRClientDescribeRepos struct {
	AWSRegions []string
}

type MockedECRClientDescribeImages struct {
	AWSRegions []string
}

func (m *MockedECRClientDescribeRepos) DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return &ecr.DescribeRepositoriesOutput{
		Repositories: []types.Repository{
			{
				RepositoryName: aws.String("test1"),
				RepositoryUri:  aws.String("testURI"),
			},
		},
	}, nil
}

func (m *MockedECRClientDescribeImages) DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	return &ecr.DescribeImagesOutput{
		ImageDetails: []types.ImageDetail{
			{
				ImagePushedAt:    aws.Time(time.Now()),
				ImageSizeInBytes: aws.Int64(123456),
				ImageTags:        []string{"latest"},
			},
		},
	}, nil
}

func TestDescribeRepos(t *testing.T) {
	subtests := []struct {
		name            string
		outputDirectory string
		verbosity       int
		testModule      ECRModule
		expectedResult  []Repository
	}{
		{
			name:            "test1",
			outputDirectory: ".",
			verbosity:       2,
			testModule: ECRModule{
				ECRClientDescribeReposInterface:  &MockedECRClientDescribeRepos{},
				ECRClientDescribeImagesInterface: &MockedECRClientDescribeImages{},
				Caller:                           sts.GetCallerIdentityOutput{Arn: aws.String("test")},
				OutputFormat:                     "table",
				AWSProfile:                       "test",
				Goroutines:                       30,
				AWSRegions:                       AWSRegions,
			},
			expectedResult: []Repository{{
				Name:      "test1",
				URI:       "testURI:latest",
				PushedAt:  "2022-10-25 15:14:06",
				ImageTags: "latest",
				ImageSize: 123456,
			}},
		},
	}
	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.PrintECR(subtest.testModule.OutputFormat, subtest.outputDirectory, subtest.verbosity)
			for index, expectedRepo := range subtest.expectedResult {
				if expectedRepo.Name != subtest.testModule.Repositories[index].Name {
					log.Fatal("Repo name does not match expected name")
				}

			}
		})
	}
}
