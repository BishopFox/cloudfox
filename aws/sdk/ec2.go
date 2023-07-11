package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/patrickmn/go-cache"
)

type AWSEC2ClientInterface interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

func init() {
	gob.Register([]ec2Types.Instance{})
	gob.Register([]ec2Types.NetworkInterface{})
	gob.Register([]ec2Types.Snapshot{})
	gob.Register([]ec2Types.Volume{})
	gob.Register([]ec2Types.Image{})

}

func CachedEC2DescribeInstances(client AWSEC2ClientInterface, accountID string, region string) ([]ec2Types.Instance, error) {
	var PaginationControl *string
	var instances []ec2Types.Instance
	cacheKey := fmt.Sprintf("%s-ec2-DescribeInstances-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]ec2Types.Instance), nil
	}
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

func CachedEC2DescribeNetworkInterfaces(client AWSEC2ClientInterface, accountID string, region string) ([]ec2Types.NetworkInterface, error) {
	var PaginationControl *string
	var NetworkInterfaces []ec2Types.NetworkInterface
	cacheKey := fmt.Sprintf("%s-ec2-DescribeNetworkInterfaces-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]ec2Types.NetworkInterface), nil
	}
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
		for _, networkInterface := range DescribeNetworkInterfaces.NetworkInterfaces {
			NetworkInterfaces = append(NetworkInterfaces, networkInterface)
		}
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
		return cached.([]ec2Types.Snapshot), nil
	}
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
		for _, snapshot := range DescribeSnapshots.Snapshots {
			Snapshots = append(Snapshots, snapshot)
		}
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
		return cached.([]ec2Types.Volume), nil
	}
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
		for _, volume := range DescribeVolumes.Volumes {
			Volumes = append(Volumes, volume)
		}
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
		return cached.([]ec2Types.Image), nil
	}
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
		for _, image := range DescribeImages.Images {
			Images = append(Images, image)
		}
		if DescribeImages.NextToken == nil {
			break
		}
		PaginationControl = DescribeImages.NextToken
	}

	internal.Cache.Set(cacheKey, Images, cache.DefaultExpiration)
	return Images, nil

}
