package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagerTypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type SecretsManagerClientInterface interface {
	ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetResourcePolicy(context.Context, *secretsmanager.GetResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
}

func init() {
	gob.Register([]secretsmanagerTypes.SecretListEntry{})
	gob.Register(policy.Policy{})

}

func CachedSecretsManagerListSecrets(client SecretsManagerClientInterface, accountID string, region string) ([]secretsmanagerTypes.SecretListEntry, error) {
	var PaginationControl *string
	var secrets []secretsmanagerTypes.SecretListEntry
	cacheKey := fmt.Sprintf("%s-secretsmanager-ListSecrets-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "secretsmanager:ListSecrets",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]secretsmanagerTypes.SecretListEntry), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "secretsmanager:ListSecrets",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
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

func CachedSecretsManagerGetResourcePolicy(client SecretsManagerClientInterface, secretId string, region string, accountID string) (policy.Policy, error) {
	var secretPolicy policy.Policy
	var policyJSON string
	cacheKey := fmt.Sprintf("%s-secretsmanager-GetResourcePolicy-%s-%s", accountID, region, secretId)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":      "secretsmanager:GetResourcePolicy",
			"account":  accountID,
			"region":   region,
			"secretId": secretId,
			"cache":    "hit",
		}).Info("AWS API call")
		return cached.(policy.Policy), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":      "secretsmanager:GetResourcePolicy",
		"account":  accountID,
		"region":   region,
		"secretId": secretId,
		"cache":    "miss",
	}).Info("AWS API call")
	GetResourcePolicy, err := client.GetResourcePolicy(
		context.TODO(),
		&secretsmanager.GetResourcePolicyInput{
			SecretId: &secretId,
		},
		func(o *secretsmanager.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return secretPolicy, err
	}

	policyJSON = aws.ToString(GetResourcePolicy.ResourcePolicy)
	secretPolicy, err = policy.ParseJSONPolicy([]byte(policyJSON))
	if err != nil {
		return secretPolicy, fmt.Errorf("parsing policy (%s) as JSON: %s", secretId, err)
	}
	internal.Cache.Set(cacheKey, secretPolicy, cache.DefaultExpiration)
	return secretPolicy, nil
}
