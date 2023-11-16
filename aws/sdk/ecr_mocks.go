package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrTypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type MockedECRClient struct {
}

func (m *MockedECRClient) DescribeRepositories(ctx context.Context, input *ecr.DescribeRepositoriesInput, options ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return &ecr.DescribeRepositoriesOutput{
		Repositories: []ecrTypes.Repository{
			{
				RepositoryName: aws.String("repo1"),
				RepositoryUri:  aws.String("11111111111111.dkr.ecr.us-east-1.amazonaws.com/repo1"),
			},
			{
				RepositoryName: aws.String("repo2"),
				RepositoryUri:  aws.String("11111111111111.dkr.ecr.us-east-1.amazonaws.com/repo2"),
			},
		},
	}, nil
}

func (m *MockedECRClient) DescribeImages(ctx context.Context, input *ecr.DescribeImagesInput, options ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	if aws.ToString(input.RepositoryName) == "repo1" {
		return &ecr.DescribeImagesOutput{
			ImageDetails: []ecrTypes.ImageDetail{
				{
					ImageTags: []string{
						"customtag",
						"tag2",
					},
					ImagePushedAt:    aws.Time(time.Date(2022, 10, 25, 15, 14, 0, 0, time.UTC)),
					ImageSizeInBytes: aws.Int64(123456),
				},
			},
		}, nil
	} else if aws.ToString(input.RepositoryName) == "repo2" {
		return &ecr.DescribeImagesOutput{
			ImageDetails: []ecrTypes.ImageDetail{
				{
					ImageTags: []string{
						"latest",
					},
					ImagePushedAt:    aws.Time(time.Date(2021, 10, 15, 11, 14, 0, 0, time.UTC)),
					ImageSizeInBytes: aws.Int64(2222222),
				},
			},
		}, nil
	} else {
		return &ecr.DescribeImagesOutput{
			ImageDetails: []ecrTypes.ImageDetail{
				{
					ImageTags: []string{
						"customtag",
						"tag2",
					},
					ImagePushedAt:    aws.Time(time.Date(2022, 10, 25, 15, 14, 0, 0, time.UTC)),
					ImageSizeInBytes: aws.Int64(111),
				},
				{
					ImageTags: []string{
						"latest",
					},
					ImagePushedAt:    aws.Time(time.Date(2021, 10, 15, 11, 14, 0, 0, time.UTC)),
					ImageSizeInBytes: aws.Int64(333),
				},
			},
		}, nil
	}

}

func (m *MockedECRClient) GetRepositoryPolicy(ctx context.Context, input *ecr.GetRepositoryPolicyInput, options ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
	return &ecr.GetRepositoryPolicyOutput{
		PolicyText: aws.String(`{
			"Version": "2008-10-17",
			"Statement": [
			  {
				"Sid": "AllowPushPull",
				"Effect": "Allow",
				"Principal": {
				  "AWS": [
					"arn:aws:iam::123456789012:root",
					"arn:aws:iam::123456789012:user/MyUser"
					]
				},
				"Action": [
										
				  "ecr:GetDownloadUrlForLayer",
				  "ecr:BatchGetImage",
				  "ecr:BatchCheckLayerAvailability",
				  "ecr:PutImage",
				  "ecr:InitiateLayerUpload",
				  "ecr:UploadLayerPart",
				  "ecr:CompleteLayerUpload"
				]
										
			}
			]
		}`),
	}, nil
}
