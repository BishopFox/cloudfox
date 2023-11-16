package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type MockedS3Client struct {
}

func (m *MockedS3Client) ListBuckets(ctx context.Context, input *s3.ListBucketsInput, options ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{
		Buckets: []s3Types.Bucket{
			{
				Name: aws.String("bucket1"),
			},
			{
				Name: aws.String("bucket2"),
			},
		},
	}, nil
}

func (m *MockedS3Client) GetBucketLocation(ctx context.Context, input *s3.GetBucketLocationInput, options ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return &s3.GetBucketLocationOutput{
		LocationConstraint: s3Types.BucketLocationConstraintUsWest1,
	}, nil
}

func (m *MockedS3Client) GetBucketPolicy(ctx context.Context, input *s3.GetBucketPolicyInput, options ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	return &s3.GetBucketPolicyOutput{
		Policy: aws.String(`{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Sid": "AWSCloudTrailAclCheck20150319",
					"Effect": "Allow",
					"Principal": {
						"Service": "cloudtrail.amazonaws.com"
					},
					"Action": "s3:GetBucketAcl",
					"Resource": "arn:aws:s3:::bucket1"
				},
				{
					"Sid": "AWSCloudTrailWrite20150319",
					"Effect": "Allow",
					"Principal": {
						"Service": "cloudtrail.amazonaws.com"
					},
					"Action": "s3:PutObject",
					"Resource": "arn:aws:s3:::bucket1/AWSLogs/123456789012/*",
					"Condition": {
						"StringEquals": {
							"s3:x-amz-acl": "bucket-owner-full-control"
						}
					}
				}
			]
		}`),
	}, nil
}

func (m *MockedS3Client) GetPublicAccessBlock(ctx context.Context, input *s3.GetPublicAccessBlockInput, options ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return &s3.GetPublicAccessBlockOutput{
		PublicAccessBlockConfiguration: &s3Types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       true,
			BlockPublicPolicy:     true,
			IgnorePublicAcls:      true,
			RestrictPublicBuckets: true,
		},
	}, nil
}
