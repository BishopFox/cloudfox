package sdk

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type MockedKMSClient struct {
}

func (m *MockedKMSClient) ListKeys(ctx context.Context, input *kms.ListKeysInput, options ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	return &kms.ListKeysOutput{
		Keys: []kmsTypes.KeyListEntry{
			{
				KeyId:  aws.String("key1"),
				KeyArn: aws.String("arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"),
			},
		},
	}, nil
}

func (m *MockedKMSClient) GetKeyPolicy(ctx context.Context, input *kms.GetKeyPolicyInput, options ...func(options *kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	return &kms.GetKeyPolicyOutput{
		Policy: aws.String(`{
			"Version": "2012-10-17",
			"Id": "key-default-1",
			"Statement": [
				{
					"Sid": "Enable IAM User Permissions",
					"Effect": "Allow",
					"Principal": {
						"AWS": "arn:aws:iam::123456789012:root"
					},
					"Action": "kms:*",
					"Resource": "*"
				}
			]
		}`),
	}, nil
}
