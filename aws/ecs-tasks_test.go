package aws

import (
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestECSTasks(t *testing.T) {
	subtests := []struct {
		name            string
		outputDirectory string
		verbosity       int
		testModule      ECSTasksModule
		expectedResult  []MappedECSTask
	}{
		{
			name:            "test1",
			outputDirectory: ".",
			verbosity:       2,
			testModule: ECSTasksModule{
				AWSProfile:     "default",
				AWSRegions:     []string{"us-east-1", "us-west-1"},
				Caller:         sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests")},
				SkipAdminCheck: true,
				Goroutines:     30,
				EC2Client:      &sdk.MockedEC2Client2{},
				ECSClient:      &sdk.MockedECSClient{},
			},
			expectedResult: []MappedECSTask{{
				Cluster:       "MyCluster",
				ID:            "74de0355a10a4f979ac495c14EXAMPLE",
				ContainerName: "web",
				ExternalIP:    "203.0.113.12",
				Role:          "test123",
			}},
		},
	}
	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.ECSTasks(subtest.outputDirectory, subtest.verbosity)
			for index, expectedTask := range subtest.expectedResult {
				if expectedTask.Cluster != subtest.testModule.MappedECSTasks[index].Cluster {
					log.Fatal("Cluster name does not match expected value")
				}
				if expectedTask.ContainerName != subtest.testModule.MappedECSTasks[index].ContainerName {
					log.Fatal("Container name does not match expected value")
				}
			}
		})
	}
}
