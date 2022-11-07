package aws

import (
	"context"
	"encoding/json"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type mockedDescribeNetworkInterfacesClient2 struct {
	describeNetworkInterfaces DescribeNetworkInterfaces
}

func (c *mockedDescribeNetworkInterfacesClient2) DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, f ...func(o *ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
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

func TestElasticNetworkInterfaces(t *testing.T) {
	m := ElasticNetworkInterfacesModule{
		AWSProfile:                      "default",
		AWSRegions:                      []string{"us-east-1", "us-west-1"},
		Caller:                          sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests")},
		DescribeNetworkInterfacesClient: &mockedDescribeNetworkInterfacesClient2{},
	}
	m.ElasticNetworkInterfaces("table", ".", 3)
}
