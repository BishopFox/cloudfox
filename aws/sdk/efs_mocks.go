package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efsTypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
)

type MockedEfsClient struct {
}

func (m *MockedEfsClient) DescribeFileSystems(ctx context.Context, input *efs.DescribeFileSystemsInput, options ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	return &efs.DescribeFileSystemsOutput{
		FileSystems: []efsTypes.FileSystemDescription{
			{
				FileSystemId: aws.String("fs-12345678"),
			},
			{
				FileSystemId: aws.String("fs-87654321"),
			},
		},
	}, nil
}

func (m *MockedEfsClient) DescribeMountTargets(ctx context.Context, input *efs.DescribeMountTargetsInput, options ...func(*efs.Options)) (*efs.DescribeMountTargetsOutput, error) {
	return &efs.DescribeMountTargetsOutput{
		MountTargets: []efsTypes.MountTargetDescription{
			{
				MountTargetId: aws.String("fsmt-12345678"),
				FileSystemId:  aws.String("fs-12345678"),
				IpAddress:     aws.String("10.1.1.1"),
			},
			{
				MountTargetId: aws.String("fsmt-87654321"),
				FileSystemId:  aws.String("fs-87654321"),
				IpAddress:     aws.String("10.2.2.2.2"),
			},
		},
	}, nil
}

func (m *MockedEfsClient) DescribeAccessPoints(ctx context.Context, input *efs.DescribeAccessPointsInput, options ...func(*efs.Options)) (*efs.DescribeAccessPointsOutput, error) {
	return &efs.DescribeAccessPointsOutput{
		AccessPoints: []efsTypes.AccessPointDescription{
			{
				AccessPointId: aws.String("fsap-12345678"),
				FileSystemId:  aws.String("fs-12345678"),
				Name:          aws.String("fsap-12345678"),
				PosixUser: &efsTypes.PosixUser{
					Gid: aws.Int64(1000),
					Uid: aws.Int64(1000),
				},
			},
			{
				AccessPointId: aws.String("fsap-87654321"),
				FileSystemId:  aws.String("fs-87654321"),
				Name:          aws.String("fsap-12345679"),
				PosixUser: &efsTypes.PosixUser{
					Gid: aws.Int64(1000),
					Uid: aws.Int64(1000),
				},
			},
		},
	}, nil
}
