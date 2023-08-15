package sdk

// create test for the Cached EC2 functions.  Create a mocked client and mocked functions for each of the methods used in the ec2.go file

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const DESCRIBE_NETWORK_INTEFACES_TEST_FILE = "./test-data/describe-network-interfaces.json"
const DESCRIBE_INSTANCES_TEST_FILE = "./test-data/ec2-describeInstances.json"
const DESCRIBE_SNAPSHOTS_TEST_FILE = "./test-data/ec2-describeSnapshots.json"
const DESCRIBE_VOLUMES_TEST_FILE = "./test-data/ec2-describeVolumes.json"
const DESCRIBE_IMAGES_TEST_FILE = "./test-data/ec2-describeImages.json"

type MockedEC2Client2 struct {
	describeNetworkInterfaces DescribeNetworkInterfaces
	describeInstances         DescribeInstances
	describeSnapshots         DescribeSnapshots
	describeVolumes           DescribeVolumes
	describeImages            DescribeImages
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

type DescribeImages struct {
	Images []struct {
		Architecture        string `json:"Architecture"`
		BlockDeviceMappings []struct {
			DeviceName string `json:"DeviceName"`
			Ebs        struct {
				DeleteOnTermination bool   `json:"DeleteOnTermination"`
				SnapshotID          string `json:"SnapshotId"`
				VolumeSize          int    `json:"VolumeSize"`
				VolumeType          string `json:"VolumeType"`
			} `json:"Ebs"`
		} `json:"BlockDeviceMappings"`
		CreationDate  string `json:"CreationDate"`
		Description   string `json:"Description"`
		EnaSupport    bool   `json:"EnaSupport"`
		Hypervisor    string `json:"Hypervisor"`
		ImageID       string `json:"ImageId"`
		ImageLocation string `json:"ImageLocation"`
		ImageType     string `json:"ImageType"`
		KernelID      string `json:"KernelId"`
		Name          string `json:"Name"`
		OwnerAlias    string `json:"OwnerAlias"`
		OwnerID       string `json:"OwnerId"`
		Platform      string `json:"Platform"`
		ProductCodes  []struct {
			ProductCodeID   string `json:"ProductCodeId"`
			ProductCodeType string `json:"ProductCodeType"`
		} `json:"ProductCodes"`
		Public          bool   `json:"Public"`
		RamdiskID       string `json:"RamdiskId"`
		RootDeviceName  string `json:"RootDeviceName"`
		RootDeviceType  string `json:"RootDeviceType"`
		SriovNetSupport string `json:"SriovNetSupport"`
		State           string `json:"State"`
		StateReason     struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"StateReason"`
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
		VirtualizationType string `json:"VirtualizationType"`
	} `json:"Images"`
	NextToken string `json:"NextToken"`
}

type DescribeSnapshots struct {
	Snapshots []struct {
		DataEncryptionKeyID string    `json:"DataEncryptionKeyId"`
		Description         string    `json:"Description"`
		Encrypted           bool      `json:"Encrypted"`
		KMSKeyID            string    `json:"KmsKeyId"`
		OwnerAlias          string    `json:"OwnerAlias"`
		OwnerID             string    `json:"OwnerId"`
		Progress            string    `json:"Progress"`
		SnapshotID          string    `json:"SnapshotId"`
		StartTime           time.Time `json:"StartTime"`
		State               string    `json:"State"`
		StateMessage        string    `json:"StateMessage"`
		TagSet              []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
		VolumeID   string `json:"VolumeId"`
		VolumeSize int    `json:"VolumeSize"`
	} `json:"Snapshots"`
}

type DescribeVolumes struct {
	Volumes []struct {
		Attachments []struct {
			AttachTime          time.Time `json:"AttachTime"`
			DeleteOnTermination bool      `json:"DeleteOnTermination"`
			Device              string    `json:"Device"`
			InstanceID          string    `json:"InstanceId"`
			State               string    `json:"State"`
			VolumeID            string    `json:"VolumeId"`
		} `json:"Attachments"`
		AvailabilityZone string `json:"AvailabilityZone"`
		CreateTime       string `json:"CreateTime"`
		Encrypted        bool   `json:"Encrypted"`
		KMSKeyID         string `json:"KmsKeyId"`
		Size             int    `json:"Size"`
		SnapshotID       string `json:"SnapshotId"`
		State            string `json:"State"`
		VolumeID         string `json:"VolumeId"`
	} `json:"Volumes"`
}

func (c *MockedEC2Client2) DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, f ...func(o *ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
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

func (c *MockedEC2Client2) DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, f ...func(o *ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
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

func (c *MockedEC2Client2) DescribeVolumes(ctx context.Context, input *ec2.DescribeVolumesInput, f ...func(o *ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	var volumes []ec2types.Volume
	err := json.Unmarshal(readTestFile(DESCRIBE_VOLUMES_TEST_FILE), &c.describeVolumes)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_VOLUMES_TEST_FILE)
	}
	for _, mockedVolume := range c.describeVolumes.Volumes {
		for _, inputVolumeID := range input.VolumeIds {
			if mockedVolume.VolumeID == inputVolumeID {
				volumes = append(volumes, ec2types.Volume{
					VolumeId: aws.String(mockedVolume.VolumeID),
					Size:     aws.Int32(int32(mockedVolume.Size)),
					Attachments: []ec2types.VolumeAttachment{
						{
							InstanceId: aws.String(mockedVolume.Attachments[0].InstanceID),
						},
					},
				})
			}
		}
	}
	return &ec2.DescribeVolumesOutput{Volumes: volumes}, nil
}

func (c *MockedEC2Client2) DescribeSnapshots(ctx context.Context, input *ec2.DescribeSnapshotsInput, f ...func(o *ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	var snapshots []ec2types.Snapshot
	err := json.Unmarshal(readTestFile(DESCRIBE_SNAPSHOTS_TEST_FILE), &c.describeSnapshots)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_SNAPSHOTS_TEST_FILE)
	}
	for _, mockedSnapshot := range c.describeSnapshots.Snapshots {
		for _, inputSnapshotID := range input.SnapshotIds {
			if mockedSnapshot.SnapshotID == inputSnapshotID {
				snapshots = append(snapshots, ec2types.Snapshot{
					SnapshotId: aws.String(mockedSnapshot.SnapshotID),
					VolumeId:   aws.String(mockedSnapshot.VolumeID),
					State:      ec2types.SnapshotState(mockedSnapshot.State),
				})
			}
		}
	}
	return &ec2.DescribeSnapshotsOutput{Snapshots: snapshots}, nil
}

func (c *MockedEC2Client2) DescribeImages(ctx context.Context, input *ec2.DescribeImagesInput, f ...func(o *ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	var images []ec2types.Image
	err := json.Unmarshal(readTestFile(DESCRIBE_IMAGES_TEST_FILE), &c.describeImages)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_IMAGES_TEST_FILE)
	}
	for _, mockedImage := range c.describeImages.Images {
		for _, inputImageID := range input.ImageIds {
			if mockedImage.ImageID == inputImageID {
				images = append(images, ec2types.Image{
					ImageId: aws.String(mockedImage.ImageID),
					Name:    aws.String(mockedImage.Name),
				})
			}
		}
	}
	return &ec2.DescribeImagesOutput{Images: images}, nil
}
