package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type AWSEC2ClientInterface interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeInstanceAttribute(context.Context, *ec2.DescribeInstanceAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceAttributeOutput, error)
	DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(options *ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
}

func init() {
	gob.Register([]ec2Types.Instance{})
	gob.Register([]ec2Types.NetworkInterface{})
	gob.Register([]ec2Types.Snapshot{})
	gob.Register([]ec2Types.Volume{})
	gob.Register([]ec2Types.Image{})
	gob.Register([]ec2Types.VpcEndpoint{})
}

func CachedEC2DescribeInstances(client AWSEC2ClientInterface, accountID string, region string) ([]ec2Types.Instance, error) {
	var PaginationControl *string
	var instances []ec2Types.Instance
	cacheKey := fmt.Sprintf("%s-ec2-DescribeInstances-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "ec2:DescribeInstances",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]ec2Types.Instance), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "ec2:DescribeInstances",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeInstances, err := client.DescribeInstances(
			context.TODO(),
			&ec2.DescribeInstancesInput{
				NextToken: PaginationControl,
			},
			func(o *ec2.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return instances, err
		}

		for _, reservation := range DescribeInstances.Reservations {
			instances = append(instances, reservation.Instances...)
		}

		//pagination
		if DescribeInstances.NextToken == nil {
			break
		}
		PaginationControl = DescribeInstances.NextToken
	}

	internal.Cache.Set(cacheKey, instances, cache.DefaultExpiration)
	return instances, nil
}

func CachedEC2DescribeInstanceAttributeUserData(client AWSEC2ClientInterface, accountID string, region string, instanceID string) (string, error) {
	cacheKey := fmt.Sprintf("%s-ec2-DescribeInstanceAttributeUserData-%s-%s", accountID, region, instanceID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":      "ec2:DescribeInstanceAttribute",
			"account":  accountID,
			"region":   region,
			"instance": instanceID,
			"cache":    "hit",
		}).Info("AWS API call")
		return cached.(string), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":      "ec2:DescribeInstanceAttribute",
		"account":  accountID,
		"region":   region,
		"instance": instanceID,
		"cache":    "miss",
	}).Info("AWS API call")
	DescribeInstanceAttribute, err := client.DescribeInstanceAttribute(
		context.TODO(),
		&ec2.DescribeInstanceAttributeInput{
			Attribute:  ec2Types.InstanceAttributeNameUserData,
			InstanceId: &instanceID,
		},
		func(o *ec2.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return "", err
	}
	internal.Cache.Set(cacheKey, aws.ToString(DescribeInstanceAttribute.UserData.Value), cache.DefaultExpiration)

	return aws.ToString(DescribeInstanceAttribute.UserData.Value), nil
}

func CachedEC2DescribeNetworkInterfaces(client AWSEC2ClientInterface, accountID string, region string) ([]ec2Types.NetworkInterface, error) {
	var PaginationControl *string
	var NetworkInterfaces []ec2Types.NetworkInterface
	cacheKey := fmt.Sprintf("%s-ec2-DescribeNetworkInterfaces-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "ec2:DescribeNetworkInterfaces",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]ec2Types.NetworkInterface), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "ec2:DescribeNetworkInterfaces",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeNetworkInterfaces, err := client.DescribeNetworkInterfaces(
			context.TODO(),
			&(ec2.DescribeNetworkInterfacesInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return NetworkInterfaces, err
		}
		NetworkInterfaces = append(NetworkInterfaces, DescribeNetworkInterfaces.NetworkInterfaces...)

		if DescribeNetworkInterfaces.NextToken == nil {
			break
		}
		PaginationControl = DescribeNetworkInterfaces.NextToken
	}

	internal.Cache.Set(cacheKey, NetworkInterfaces, cache.DefaultExpiration)
	return NetworkInterfaces, nil
}

func CachedEC2DescribeSnapshots(client AWSEC2ClientInterface, accountID string, region string) ([]ec2Types.Snapshot, error) {
	var PaginationControl *string
	var Snapshots []ec2Types.Snapshot
	cacheKey := fmt.Sprintf("%s-ec2-DescribeSnapshots-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "ec2:DescribeSnapshots",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]ec2Types.Snapshot), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "ec2:DescribeSnapshots",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeSnapshots, err := client.DescribeSnapshots(
			context.TODO(),
			&(ec2.DescribeSnapshotsInput{
				NextToken: PaginationControl,
				OwnerIds:  []string{accountID},
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return Snapshots, err
		}
		Snapshots = append(Snapshots, DescribeSnapshots.Snapshots...)

		if DescribeSnapshots.NextToken == nil {
			break
		}
		PaginationControl = DescribeSnapshots.NextToken
	}

	internal.Cache.Set(cacheKey, Snapshots, cache.DefaultExpiration)
	return Snapshots, nil
}

func CachedEC2DescribeVolumes(client AWSEC2ClientInterface, accountID string, region string) ([]ec2Types.Volume, error) {
	var PaginationControl *string
	var Volumes []ec2Types.Volume
	cacheKey := fmt.Sprintf("%s-ec2-DescribeVolumes-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "ec2:DescribeVolumes",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]ec2Types.Volume), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "ec2:DescribeVolumes",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeVolumes, err := client.DescribeVolumes(
			context.TODO(),
			&(ec2.DescribeVolumesInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return Volumes, err
		}
		Volumes = append(Volumes, DescribeVolumes.Volumes...)

		if DescribeVolumes.NextToken == nil {
			break
		}
		PaginationControl = DescribeVolumes.NextToken
	}

	internal.Cache.Set(cacheKey, Volumes, cache.DefaultExpiration)
	return Volumes, nil
}

func CachedEC2DescribeImages(client AWSEC2ClientInterface, accountID string, region string) ([]ec2Types.Image, error) {
	var PaginationControl *string
	var Images []ec2Types.Image
	cacheKey := fmt.Sprintf("%s-ec2-DescribeImages-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "ec2:DescribeImages",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]ec2Types.Image), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "ec2:DescribeImages",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeImages, err := client.DescribeImages(
			context.TODO(),
			&(ec2.DescribeImagesInput{
				Owners:    []string{accountID},
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return Images, err
		}
		Images = append(Images, DescribeImages.Images...)

		if DescribeImages.NextToken == nil {
			break
		}
		PaginationControl = DescribeImages.NextToken
	}

	internal.Cache.Set(cacheKey, Images, cache.DefaultExpiration)
	return Images, nil
}

func CachedEC2DescribeVpcEndpoints(client AWSEC2ClientInterface, accountID string, region string) ([]ec2Types.VpcEndpoint, error) {
	var PaginationControl *string
	var VpcEndpoints []ec2Types.VpcEndpoint
	cacheKey := fmt.Sprintf("%s-ec2-DescribeVpcEndpoints-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "ec2:DescribeVpcEndpoints",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]ec2Types.VpcEndpoint), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "ec2:DescribeVpcEndpoints",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		DescribeVpcEndpoints, err := client.DescribeVpcEndpoints(
			context.TODO(),
			&(ec2.DescribeVpcEndpointsInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return VpcEndpoints, err
		}
		VpcEndpoints = append(VpcEndpoints, DescribeVpcEndpoints.VpcEndpoints...)

		if DescribeVpcEndpoints.NextToken == nil {
			break
		}
		PaginationControl = DescribeVpcEndpoints.NextToken
	}
	internal.Cache.Set(cacheKey, VpcEndpoints, cache.DefaultExpiration)
	return VpcEndpoints, nil
}
