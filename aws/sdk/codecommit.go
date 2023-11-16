package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/codecommit"
	codeCommitTypes "github.com/aws/aws-sdk-go-v2/service/codecommit/types"
	"github.com/patrickmn/go-cache"
)

type AWSCodeCommitClientInterface interface {
	ListRepositories(context.Context, *codecommit.ListRepositoriesInput, ...func(*codecommit.Options)) (*codecommit.ListRepositoriesOutput, error)
}

func init() {
	gob.Register([]codeCommitTypes.RepositoryNameIdPair{})
}

func CachedCodeCommitListRepositories(client AWSCodeCommitClientInterface, accountID string, region string) ([]codeCommitTypes.RepositoryNameIdPair, error) {
	var PaginationControl *string
	var repositories []codeCommitTypes.RepositoryNameIdPair
	cacheKey := fmt.Sprintf("%s-codecommit-ListRepositories-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]codeCommitTypes.RepositoryNameIdPair), nil
	}
	for {
		ListRepositories, err := client.ListRepositories(
			context.TODO(),
			&codecommit.ListRepositoriesInput{
				NextToken: PaginationControl,
			},
			func(o *codecommit.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return repositories, err
		}

		repositories = append(repositories, ListRepositories.Repositories...)

		//pagination
		if ListRepositories.NextToken == nil {
			break
		}
		PaginationControl = ListRepositories.NextToken
	}

	internal.Cache.Set(cacheKey, repositories, cache.DefaultExpiration)
	return repositories, nil
}
