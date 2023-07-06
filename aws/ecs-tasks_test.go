package aws

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"testing"
	"time"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const DESCRIBE_TASKS_TEST_FILE = "./test-data/describe-tasks.json"
const DESCRIBE_NETWORK_INTEFACES_TEST_FILE = "./test-data/describe-network-interfaces.json"
const DESCRIBE_INSTANCES_TEST_FILE = "./test-data/ec2-describeInstances.json"

type mockedECSClient struct {
	describeTasks DescribeTasks
}
type mockedEC2Client struct {
	describeNetworkInterfaces DescribeNetworkInterfaces
	describeInstances         DescribeInstances
}

type ListTasks struct {
	TaskArns []string `json:"taskArns"`
}

type DescribeTasks struct {
	Tasks []struct {
		Attachments []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Status  string `json:"status"`
			Details []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"details"`
		} `json:"attachments"`
		Attributes []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"attributes"`
		AvailabilityZone string `json:"availabilityZone"`
		ClusterArn       string `json:"clusterArn"`
		Connectivity     string `json:"connectivity"`
		ConnectivityAt   string `json:"connectivityAt"`
		Containers       []struct {
			ContainerArn      string        `json:"containerArn"`
			TaskArn           string        `json:"taskArn"`
			Name              string        `json:"name"`
			Image             string        `json:"image"`
			RuntimeID         string        `json:"runtimeId"`
			LastStatus        string        `json:"lastStatus"`
			NetworkBindings   []interface{} `json:"networkBindings"`
			NetworkInterfaces []struct {
				AttachmentID       string `json:"attachmentId"`
				PrivateIpv4Address string `json:"privateIpv4Address"`
			} `json:"networkInterfaces"`
			HealthStatus string `json:"healthStatus"`
			CPU          string `json:"cpu"`
			Memory       string `json:"memory"`
		} `json:"containers"`
		CPU                  string `json:"cpu"`
		CreatedAt            string `json:"createdAt"`
		DesiredStatus        string `json:"desiredStatus"`
		EnableExecuteCommand bool   `json:"enableExecuteCommand"`
		Group                string `json:"group"`
		HealthStatus         string `json:"healthStatus"`
		LastStatus           string `json:"lastStatus"`
		LaunchType           string `json:"launchType"`
		Memory               string `json:"memory"`
		Overrides            struct {
			ContainerOverrides []struct {
				Name string `json:"name"`
			} `json:"containerOverrides"`
			InferenceAcceleratorOverrides []interface{} `json:"inferenceAcceleratorOverrides"`
		} `json:"overrides"`
		PlatformVersion   string        `json:"platformVersion"`
		PlatformFamily    string        `json:"platformFamily"`
		PullStartedAt     string        `json:"pullStartedAt"`
		PullStoppedAt     string        `json:"pullStoppedAt"`
		StartedAt         string        `json:"startedAt"`
		StartedBy         string        `json:"startedBy"`
		Tags              []interface{} `json:"tags"`
		TaskArn           string        `json:"taskArn"`
		TaskDefinitionArn string        `json:"taskDefinitionArn"`
		Version           int           `json:"version"`
		EphemeralStorage  struct {
			SizeInGiB int `json:"sizeInGiB"`
		} `json:"ephemeralStorage"`
	} `json:"tasks"`
	Failures []interface{} `json:"failures"`
}

type DescribeNetworkInterfaces struct {
	NetworkInterfaces []struct {
		Status          string `json:"Status"`
		MacAddress      string `json:"MacAddress"`
		SourceDestCheck bool   `json:"SourceDestCheck"`
		VpcID           string `json:"VpcId"`
		Description     string `json:"Description"`
		Association     struct {
			PublicIP      string `json:"PublicIp"`
			AssociationID string `json:"AssociationId"`
			PublicDNSName string `json:"PublicDnsName"`
			IPOwnerID     string `json:"IpOwnerId"`
		} `json:"Association"`
		NetworkInterfaceID string `json:"NetworkInterfaceId"`
		PrivateIPAddresses []struct {
			PrivateDNSName string `json:"PrivateDnsName"`
			Association    struct {
				PublicIP      string `json:"PublicIp"`
				AssociationID string `json:"AssociationId"`
				PublicDNSName string `json:"PublicDnsName"`
				IPOwnerID     string `json:"IpOwnerId"`
			} `json:"Association"`
			Primary          bool   `json:"Primary"`
			PrivateIPAddress string `json:"PrivateIpAddress"`
		} `json:"PrivateIpAddresses"`
		RequesterManaged bool          `json:"RequesterManaged"`
		Ipv6Addresses    []interface{} `json:"Ipv6Addresses"`
		PrivateDNSName   string        `json:"PrivateDnsName,omitempty"`
		AvailabilityZone string        `json:"AvailabilityZone"`
		Attachment       struct {
			Status              string    `json:"Status"`
			DeviceIndex         int       `json:"DeviceIndex"`
			AttachTime          time.Time `json:"AttachTime"`
			InstanceID          string    `json:"InstanceId"`
			DeleteOnTermination bool      `json:"DeleteOnTermination"`
			AttachmentID        string    `json:"AttachmentId"`
			InstanceOwnerID     string    `json:"InstanceOwnerId"`
		} `json:"Attachment"`
		Groups []struct {
			GroupName string `json:"GroupName"`
			GroupID   string `json:"GroupId"`
		} `json:"Groups"`
		SubnetID         string        `json:"SubnetId"`
		OwnerID          string        `json:"OwnerId"`
		TagSet           []interface{} `json:"TagSet"`
		PrivateIPAddress string        `json:"PrivateIpAddress"`
	} `json:"NetworkInterfaces"`
}

type DescribeInstances struct {
	Reservations []struct {
		Instances []struct {
			AmiLaunchIndex int    `json:"AmiLaunchIndex"`
			ImageID        string `json:"ImageId"`
			InstanceID     string `json:"InstanceId"`
			InstanceType   string `json:"InstanceType"`
			KernelID       string `json:"KernelId"`
			KeyName        string `json:"KeyName"`
			LaunchTime     string `json:"LaunchTime"`
			Monitoring     struct {
				State string `json:"State"`
			} `json:"Monitoring"`
			Placement struct {
				AvailabilityZone string `json:"AvailabilityZone"`
				GroupName        string `json:"GroupName"`
				Tenancy          string `json:"Tenancy"`
			} `json:"Placement"`
			Platform            string `json:"Platform"`
			PrivateDNS          string `json:"PrivateDnsName"`
			PrivateIP           string `json:"PrivateIpAddress"`
			PublicDNS           string `json:"PublicDnsName"`
			PublicIP            string `json:"PublicIpAddress"`
			State               string `json:"State"`
			SubnetID            string `json:"SubnetId"`
			VpcID               string `json:"VpcId"`
			Architecture        string `json:"Architecture"`
			BlockDeviceMappings []struct {
				DeviceName string `json:"DeviceName"`
				Ebs        struct {
					AttachTime          time.Time `json:"AttachTime"`
					DeleteOnTermination bool      `json:"DeleteOnTermination"`
					Status              string    `json:"Status"`
					VolumeID            string    `json:"VolumeId"`
				} `json:"Ebs"`
			} `json:"BlockDeviceMappings"`
			ClientToken        string `json:"ClientToken"`
			EbsOptimized       bool   `json:"EbsOptimized"`
			Hypervisor         string `json:"Hypervisor"`
			IamInstanceProfile struct {
				Arn string `json:"Arn"`
				ID  string `json:"Id"`
			} `json:"IamInstanceProfile"`
			NetworkInterfaces []struct {
				Attachment struct {
					AttachTime          time.Time `json:"AttachTime"`
					AttachmentID        string    `json:"AttachmentId"`
					DeleteOnTermination bool      `json:"DeleteOnTermination"`
					DeviceIndex         int       `json:"DeviceIndex"`
					Status              string    `json:"Status"`
				} `json:"Attachment"`
				Description string `json:"Description"`
				Groups      []struct {
					GroupName string `json:"GroupName"`
					GroupID   string `json:"GroupId"`
				} `json:"Groups"`
				MacAddress         string `json:"MacAddress"`
				NetworkInterfaceID string `json:"NetworkInterfaceId"`
				OwnerID            string `json:"OwnerId"`
				PrivateDNSName     string `json:"PrivateDnsName"`
				PrivateIPAddress   string `json:"PrivateIpAddress"`
				PrivateIPAddresses []struct {
					Association struct {
						IPOwnerID     string `json:"IpOwnerId"`
						PublicDNSName string `json:"PublicDnsName"`
						PublicIP      string `json:"PublicIp"`
					} `json:"Association"`
					Primary          bool   `json:"Primary"`
					PrivateDNSName   string `json:"PrivateDnsName"`
					PrivateIPAddress string `json:"PrivateIpAddress"`
				} `json:"PrivateIpAddresses"`
				SourceDestCheck bool   `json:"SourceDestCheck"`
				Status          string `json:"Status"`
				SubnetID        string `json:"SubnetId"`
				VpcID           string `json:"VpcId"`
			} `json:"NetworkInterfaces"`
			RootDeviceName string `json:"RootDeviceName"`
			RootDeviceType string `json:"RootDeviceType"`
			SecurityGroups []struct {
				GroupName string `json:"GroupName"`
				GroupID   string `json:"GroupId"`
			} `json:"SecurityGroups"`
			SourceDestCheck bool `json:"SourceDestCheck"`
			StateReason     struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"StateReason"`
			Tags []struct {
				Key   string `json:"Key"`
				Value string `json:"Value"`
			} `json:"Tags"`
			VirtualizationType string `json:"VirtualizationType"`
		} `json:"Instances"`
		OwnerID       string `json:"OwnerId"`
		RequesterID   string `json:"RequesterId"`
		ReservationID string `json:"ReservationId"`
	} `json:"Reservations"`
}

func readTestFile(testFile string) []byte {
	file, err := os.ReadFile(testFile)
	if err != nil {
		log.Fatalf("can't read file %s", testFile)
	}
	return file
}

func (c *mockedECSClient) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{
		"arn:aws:ecs:us-east-1:123456789012:cluster/MyCluster",
		"arn:aws:ecs:us-east-1:123456789012:cluster/MyCluster2",
		"arn:aws:ecs:us-east-1:123456789012:cluster/MyCluster3",
	}}, nil
}

func (c *mockedECSClient) ListTasks(ctx context.Context, input *ecs.ListTasksInput, f ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{TaskArns: []string{
		"arn:aws:ecs:us-east-1:123456789012:task/MyCluster/74de0355a10a4f979ac495c14EXAMPLE",
		"arn:aws:ecs:us-east-1:123456789012:task/MyCluster/d789e94343414c25b9f6bd59eEXAMPLE",
	}}, nil
}

func (c *mockedECSClient) DescribeTasks(ctx context.Context, input *ecs.DescribeTasksInput, f ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	err := json.Unmarshal(readTestFile(DESCRIBE_TASKS_TEST_FILE), &c.describeTasks)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_TASKS_TEST_FILE)
	}
	var tasks []ecsTypes.Task
	for _, mockedTask := range c.describeTasks.Tasks {
		if mockedTask.ClusterArn == aws.ToString(input.Cluster) {
			for _, inputTask := range input.Tasks {
				if mockedTask.TaskArn == inputTask {
					var attachments []ecsTypes.Attachment
					for _, a := range mockedTask.Attachments {
						var deets []ecsTypes.KeyValuePair
						for _, detail := range a.Details {
							deets = append(deets, ecsTypes.KeyValuePair{
								Name:  aws.String(detail.Name),
								Value: aws.String(detail.Value)})
						}
						attachments = append(attachments, ecsTypes.Attachment{
							Type:    aws.String(a.Type),
							Details: deets,
							Id:      aws.String(a.ID),
							Status:  aws.String(a.Status),
						})
					}
					tasks = append(tasks, ecsTypes.Task{
						ClusterArn:        aws.String(mockedTask.ClusterArn),
						TaskDefinitionArn: aws.String(mockedTask.TaskDefinitionArn),
						LaunchType:        ecsTypes.LaunchType(*aws.String(mockedTask.LaunchType)),
						TaskArn:           aws.String(mockedTask.TaskArn),
						Attachments:       attachments,
					})
				}
			}
		}
	}
	return &ecs.DescribeTasksOutput{Tasks: tasks}, nil
}

func (c *mockedEC2Client) DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, f ...func(o *ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	var nics []ec2types.NetworkInterface
	err := json.Unmarshal(readTestFile(DESCRIBE_NETWORK_INTEFACES_TEST_FILE), &c.describeNetworkInterfaces)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_NETWORK_INTEFACES_TEST_FILE)
	}
	for _, mockedNic := range c.describeNetworkInterfaces.NetworkInterfaces {
		for _, inputNicID := range input.NetworkInterfaceIds {
			if mockedNic.NetworkInterfaceID == inputNicID {
				nics = append(nics, ec2types.NetworkInterface{
					Association: &ec2types.NetworkInterfaceAssociation{
						PublicIp: aws.String(mockedNic.Association.PublicIP),
					},
					NetworkInterfaceId: aws.String(mockedNic.NetworkInterfaceID)})
			}
		}
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: nics}, nil
}

func (c *mockedEC2Client) DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, f ...func(o *ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
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

func (c *mockedECSClient) DescribeTaskDefinition(ctx context.Context, input *ecs.DescribeTaskDefinitionInput, f ...func(o *ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	testTaskDefinition := ecsTypes.TaskDefinition{}
	testTaskDefinition.TaskRoleArn = aws.String("test123")
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &testTaskDefinition}, nil
}

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
				EC2Client:      &mockedEC2Client{},
				ECSClient:      &mockedECSClient{},
			},
			expectedResult: []MappedECSTask{{
				Cluster:    "MyCluster",
				ID:         "74de0355a10a4f979ac495c14EXAMPLE",
				ExternalIP: "203.0.113.12",
				Role:       "test123",
			}},
		},
	}
	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.ECSTasks(subtest.testModule.OutputFormat, subtest.outputDirectory, subtest.verbosity)
			for index, expectedTask := range subtest.expectedResult {
				if expectedTask.Cluster != subtest.testModule.MappedECSTasks[index].Cluster {
					log.Fatal("Cluster name does not match expected value")
				}
			}
		})
	}
}
