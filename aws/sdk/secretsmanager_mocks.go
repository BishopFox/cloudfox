package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagerTypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type MockedSecretsManagerClient struct {
}

func (m *MockedSecretsManagerClient) ListSecrets(ctx context.Context, input *secretsmanager.ListSecretsInput, options ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return &secretsmanager.ListSecretsOutput{
		SecretList: []secretsmanagerTypes.SecretListEntry{
			{
				Name: aws.String("secret1"),
			},
			{
				Name: aws.String("secret2"),
			},
		},
	}, nil
}

func (m *MockedSecretsManagerClient) GetResourcePolicy(ctx context.Context, input *secretsmanager.GetResourcePolicyInput, options ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	return &secretsmanager.GetResourcePolicyOutput{
		ResourcePolicy: aws.String(`{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Sid": "RetrieveSecret",
					"Effect": "Allow",
					"Principal": {
						"AWS": "arn:aws:iam::123456789012:root"
					},
					"Action": [
						"secretsmanager:GetSecretValue",
						"secretsmanager:DescribeSecret",
						"secretsmanager:ListSecretVersionIds"
					],
					"Resource": "*"
				},
				{
					"Sid": "RetrieveSecret",
					"Effect": "Allow",
					"Principal": {
						"AWS": "arn:aws:iam::123456789012:root"
					},
					"Action": [
						"secretsmanager:GetSecretValue",
						"secretsmanager:DescribeSecret",
					],
					"Resource": "*"
				}
			]
		}`),
	}, nil
}
