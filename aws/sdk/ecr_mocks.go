package sdk

import (
	"context"

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
			},
			{
				RepositoryName: aws.String("repo2"),
			},
		},
	}, nil
}

func (m *MockedECRClient) DescribeImages(ctx context.Context, input *ecr.DescribeImagesInput, options ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	return &ecr.DescribeImagesOutput{
		ImageDetails: []ecrTypes.ImageDetail{
			{
				ImageTags: []string{
					"tag1",
					"tag2",
				},
			},
			{
				ImageTags: []string{
					"tag3", "tag4", "tag5", "tag6"},
			},
		},
	}, nil
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
