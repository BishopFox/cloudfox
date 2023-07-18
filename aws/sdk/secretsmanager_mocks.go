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
