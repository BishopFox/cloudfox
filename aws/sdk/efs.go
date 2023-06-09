package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efsTypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/patrickmn/go-cache"
)

type AWSEFSClientInterface interface {
	DescribeFileSystems(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
	DescribeMountTargets(ctx context.Context, params *efs.DescribeMountTargetsInput, optFns ...func(*efs.Options)) (*efs.DescribeMountTargetsOutput, error)
	DescribeAccessPoints(ctx context.Context, params *efs.DescribeAccessPointsInput, optFns ...func(*efs.Options)) (*efs.DescribeAccessPointsOutput, error)
	DescribeFileSystemPolicy(ctx context.Context, params *efs.DescribeFileSystemPolicyInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemPolicyOutput, error)
}

func RegisterEFSTypes() {
	gob.Register([]efsTypes.FileSystemDescription{})
	gob.Register([]efsTypes.MountTargetDescription{})
	gob.Register([]efsTypes.AccessPointDescription{})
	gob.Register(policy.Policy{})
}

func CachedDescribeFileSystems(EFSClient AWSEFSClientInterface, accountID string, r string) ([]efsTypes.FileSystemDescription, error) {
	var PaginationMarker *string
	var filesystems []efsTypes.FileSystemDescription
	var err error
	cacheKey := fmt.Sprintf("%s-efs-DescribeFileSystems-%s", accountID, r)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]efsTypes.FileSystemDescription), nil
	}

	for {
		DescribeFileSystems, err := EFSClient.DescribeFileSystems(
			context.TODO(),
			&efs.DescribeFileSystemsInput{
				Marker: PaginationMarker,
			},
			func(o *efs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			return nil, err
		}

		filesystems = append(filesystems, DescribeFileSystems.FileSystems...)

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeFileSystems.Marker != nil {
			PaginationMarker = DescribeFileSystems.Marker
		} else {
			PaginationMarker = nil
			break
		}
	}
	internal.Cache.Set(cacheKey, filesystems, cache.DefaultExpiration)
	return filesystems, err
}

func CachedDescribeMountTargets(EFSClient AWSEFSClientInterface, accountID string, r string, filesystemId string) ([]efsTypes.MountTargetDescription, error) {
	var PaginationMarker *string
	var mountTargets []efsTypes.MountTargetDescription
	var err error
	cacheKey := fmt.Sprintf("%s-efs-DescribeMountTargets-%s-%s", accountID, r, filesystemId)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]efsTypes.MountTargetDescription), nil
	}

	for {
		DescribeMountTargets, err := EFSClient.DescribeMountTargets(
			context.TODO(),
			&efs.DescribeMountTargetsInput{
				FileSystemId: aws.String(filesystemId),
				Marker:       PaginationMarker,
			},
			func(o *efs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			return nil, err
		}

		mountTargets = append(mountTargets, DescribeMountTargets.MountTargets...)

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeMountTargets.Marker != nil {
			PaginationMarker = DescribeMountTargets.Marker
		} else {
			PaginationMarker = nil
			break
		}
	}
	internal.Cache.Set(cacheKey, mountTargets, cache.DefaultExpiration)
	return mountTargets, err
}

func CachedDescribeAccessPoints(EFSClient AWSEFSClientInterface, accountID string, r string, filesystemId string) ([]efsTypes.AccessPointDescription, error) {
	var PaginationMarker *string
	var accessPoints []efsTypes.AccessPointDescription
	var err error
	cacheKey := fmt.Sprintf("%s-efs-DescribeAccessPoints-%s-%s", accountID, r, filesystemId)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]efsTypes.AccessPointDescription), nil
	}
	for {
		DescribeAccessPoints, err := EFSClient.DescribeAccessPoints(
			context.TODO(),
			&efs.DescribeAccessPointsInput{
				FileSystemId: aws.String(filesystemId),
				NextToken:    PaginationMarker,
			},
			func(o *efs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			return nil, err
		}

		accessPoints = append(accessPoints, DescribeAccessPoints.AccessPoints...)

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeAccessPoints.NextToken != nil {
			PaginationMarker = DescribeAccessPoints.NextToken
		} else {
			PaginationMarker = nil
			break
		}
	}
	internal.Cache.Set(cacheKey, accessPoints, cache.DefaultExpiration)
	return accessPoints, err
}

func CachedDescribeFileSystemPolicy(EFSClient AWSEFSClientInterface, filesystemId string, r string, accountID string) (policy.Policy, error) {
	var efsPolicy policy.Policy
	var policyJSON string
	cacheKey := fmt.Sprintf("efs-%s-DescribeFileSystemPolicy-%s-%s", accountID, r, filesystemId)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(policy.Policy), nil
	}

	Policy, err := EFSClient.DescribeFileSystemPolicy(
		context.TODO(),
		&efs.DescribeFileSystemPolicyInput{
			FileSystemId: aws.String(filesystemId),
		},
		func(o *efs.Options) {
			o.Region = r
		},
	)
	if err != nil {
		sharedLogger.Error(err.Error())
		return efsPolicy, err
	}

	policyJSON = aws.ToString(Policy.Policy)
	efsPolicy, err = policy.ParseJSONPolicy([]byte(policyJSON))
	if err != nil {
		return efsPolicy, fmt.Errorf("parsing policy (%s) as JSON: %s", filesystemId, err)
	}
	internal.Cache.Set(cacheKey, efsPolicy, cache.DefaultExpiration)
	return efsPolicy, nil
}
