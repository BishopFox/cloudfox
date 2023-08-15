package aws

import (
	"testing"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestElasticNetworkInterfaces(t *testing.T) {

	m := ElasticNetworkInterfacesModule{
		AWSProfile: "default",
		AWSRegions: []string{"us-east-1", "us-west-1"},
		Caller:     sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests")},
		EC2Client:  &sdk.MockedEC2Client2{},
	}

	//m.ElasticNetworkInterfaces("table", ".", 3)
	subtests := []struct {
		name           string
		testModule     ElasticNetworkInterfacesModule
		expectedResult []MappedENI
	}{
		{
			name:       "Test ElasticNetworkInterfaces",
			testModule: m,
			expectedResult: []MappedENI{
				{
					PrivateIP:  "10.0.1.17",
					ExternalIP: "203.0.113.12",
				},
				{
					PrivateIP:  "10.0.1.149",
					ExternalIP: "198.51.100.0",
				},
			},
		},
	}
	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.ElasticNetworkInterfaces("table", ".", 3)
			for index, expectedTask := range subtest.expectedResult {
				if expectedTask.ExternalIP != subtest.testModule.MappedENIs[index].ExternalIP {
					t.Errorf("expected %s, got %s", expectedTask.ExternalIP, subtest.testModule.MappedENIs[index].ExternalIP)
				}
				if expectedTask.PrivateIP != subtest.testModule.MappedENIs[index].PrivateIP {
					t.Errorf("expected %s, got %s", expectedTask.PrivateIP, subtest.testModule.MappedENIs[index].PrivateIP)
				}

			}
		})
	}
}
