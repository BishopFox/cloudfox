package aws

import (
	"context"
	"encoding/json"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type mockedEC2Client2 struct {
	describeNetworkInterfaces DescribeNetworkInterfaces
	describeInstances         DescribeInstances
}

func (c *mockedEC2Client2) DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, f ...func(o *ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	var nics []ec2types.NetworkInterface
	err := json.Unmarshal(readTestFile(DESCRIBE_NETWORK_INTEFACES_TEST_FILE), &c.describeNetworkInterfaces)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_NETWORK_INTEFACES_TEST_FILE)
	}
	for _, mockednic := range c.describeNetworkInterfaces.NetworkInterfaces {
		nics = append(nics, ec2types.NetworkInterface{
			Association: &ec2types.NetworkInterfaceAssociation{
				PublicIp: aws.String(mockednic.Association.PublicIP),
			},
			NetworkInterfaceId: aws.String(mockednic.NetworkInterfaceID),
			PrivateIpAddress:   aws.String(mockednic.PrivateIPAddress),
			VpcId:              aws.String(mockednic.VpcID),
			Attachment:         &ec2types.NetworkInterfaceAttachment{InstanceId: aws.String(mockednic.Attachment.InstanceID)},
			Description:        aws.String(mockednic.Description),
		})
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: nics}, nil
}

func (c *mockedEC2Client2) DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, f ...func(o *ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	var instances []ec2types.Instance
	err := json.Unmarshal(readTestFile(DESCRIBE_INSTANCES_TEST_FILE), &c.describeInstances)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_INSTANCES_TEST_FILE)
	}
	for _, mockedReservation := range c.describeInstances.Reservations {
		for _, mockedInstance := range mockedReservation.Instances {
			for _, inputInstanceID := range input.InstanceIds {
				if mockedInstance.InstanceID == inputInstanceID {
					instances = append(instances, ec2types.Instance{
						InstanceId:   aws.String(mockedInstance.InstanceID),
						InstanceType: ec2types.InstanceType(mockedInstance.InstanceType),
						ImageId:      aws.String(mockedInstance.ImageID),
					})
				}
			}
		}
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{
		{Instances: instances},
	}}, nil
}

func TestElasticNetworkInterfaces(t *testing.T) {
	m := ElasticNetworkInterfacesModule{
		AWSProfile: "default",
		AWSRegions: []string{"us-east-1", "us-west-1"},
		Caller:     sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests")},
		EC2Client:  &mockedEC2Client2{},
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
