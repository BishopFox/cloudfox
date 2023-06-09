package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagerTypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/patrickmn/go-cache"
)

type SecretsManagerClientInterface interface {
	ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

func RegisterSecretsManagerTypes() {
	gob.Register([]secretsmanagerTypes.SecretListEntry{})
}

func CachedSecretsManagerListSecrets(client SecretsManagerClientInterface, accountID string, region string) ([]secretsmanagerTypes.SecretListEntry, error) {
	var PaginationControl *string
	var secrets []secretsmanagerTypes.SecretListEntry
	cacheKey := fmt.Sprintf("%s-secretsmanager-ListSecrets-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]secretsmanagerTypes.SecretListEntry), nil
	}
	for {
		ListSecrets, err := client.ListSecrets(
			context.TODO(),
			&secretsmanager.ListSecretsInput{
				NextToken: PaginationControl,
			},
			func(o *secretsmanager.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return secrets, err
		}

		secrets = append(secrets, ListSecrets.SecretList...)

		//pagination
		if ListSecrets.NextToken == nil {
			break
		}
		PaginationControl = ListSecrets.NextToken
	}

	internal.Cache.Set(cacheKey, secrets, cache.DefaultExpiration)
	return secrets, nil
}
