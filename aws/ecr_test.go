package aws

import (
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

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
				ECRClient: &sdk.MockedECRClient{},
				Caller: sts.GetCallerIdentityOutput{
					Arn:     aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests"),
					Account: aws.String("123456789012"),
				},
				AWSProfile: "test",
				Goroutines: 30,
				AWSRegions: []string{"us-east-1"},
			},
			expectedResult: []Repository{
				{
					Name:      "repo1",
					URI:       "11111111111111.dkr.ecr.us-east-1.amazonaws.com/repo1",
					PushedAt:  "2022-10-25 15:14:00",
					ImageTags: "customtag, tag2",
					ImageSize: 123456,
				},
				{
					Name:      "repo2",
					URI:       "11111111111111.dkr.ecr.us-east-1.amazonaws.com/repo2",
					PushedAt:  "2021-10-15 11:14:00",
					ImageTags: "latest",
					ImageSize: 2222222,
				}},
		},
	}

	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.PrintECR(subtest.outputDirectory, subtest.verbosity)
			for index, expectedRepo := range subtest.expectedResult {
				if expectedRepo.Name != subtest.testModule.Repositories[index].Name {
					log.Fatal("Repo name does not match expected name")
				}

			}
		})
	}
}
