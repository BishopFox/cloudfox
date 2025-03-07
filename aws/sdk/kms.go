package sdk

import (
	"context"
	"encoding/gob"
	"fmt"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/patrickmn/go-cache"
)

// KMSClientInterface is an interface for the AWS SDK KMS client.
type KMSClientInterface interface {
	GetKeyPolicy(context.Context, *kms.GetKeyPolicyInput, ...func(options *kms.Options)) (*kms.GetKeyPolicyOutput, error)
}

func init() {
	gob.Register([]kmsTypes.KeyListEntry{})
	gob.Register(policy.Policy{})
}

// CachedKMSListKeys returns a list of KMS keys for the given account and region.
func CachedKMSListKeys(client KMSClientInterface, accountID string, region string) ([]kmsTypes.KeyListEntry, error) {
	var keys []kmsTypes.KeyListEntry
	cacheKey := fmt.Sprintf("%s-kms-ListKeys-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]kmsTypes.KeyListEntry), nil
	}

	keyPaginator := kms.NewListKeysPaginator(client.(kms.ListKeysAPIClient), &kms.ListKeysInput{}, func(options *kms.ListKeysPaginatorOptions) {})

	for keyPaginator.HasMorePages() {
		output, err := keyPaginator.NextPage(context.TODO())

		if err != nil {
			return nil, err
		}

		for _, key := range output.Keys {
			keys = append(keys, key)
		}
	}

	internal.Cache.Set(cacheKey, keys, cache.DefaultExpiration)
	return keys, nil
}

// CachedKMSGetKeyPolicy returns the policy for the given KMS key.
func CachedKMSGetKeyPolicy(client KMSClientInterface, accountID string, region string, keyID string) (policy.Policy, error) {
	var keyPolicy policy.Policy
	var policyJson string
	cacheKey := fmt.Sprintf("%s-kms-GetKeyPolicy-%s-%s", accountID, region, keyID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(policy.Policy), nil
	}

	getKeyPolicy, err := client.GetKeyPolicy(
		context.TODO(),
		&kms.GetKeyPolicyInput{
			KeyId: &keyID,
		},
	)
	if err != nil {
		return keyPolicy, err
	}

	policyJson = aws.ToString(getKeyPolicy.Policy)
	keyPolicy, err = policy.ParseJSONPolicy([]byte(policyJson))
	if err != nil {
		return keyPolicy, fmt.Errorf("parsing policy (%s) as JSON: %s", keyID, err)
	}
	internal.Cache.Set(cacheKey, keyPolicy, cache.DefaultExpiration)
	return keyPolicy, nil
}
