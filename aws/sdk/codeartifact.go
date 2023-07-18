package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
	codeArtifactTypes "github.com/aws/aws-sdk-go-v2/service/codeartifact/types"
	"github.com/patrickmn/go-cache"
)

type AWSCodeArtifactClientInterface interface {
	ListDomains(context.Context, *codeartifact.ListDomainsInput, ...func(*codeartifact.Options)) (*codeartifact.ListDomainsOutput, error)
	ListRepositories(context.Context, *codeartifact.ListRepositoriesInput, ...func(*codeartifact.Options)) (*codeartifact.ListRepositoriesOutput, error)
}

func init() {
	gob.Register([]codeArtifactTypes.DomainSummary{})
	gob.Register([]codeArtifactTypes.RepositorySummary{})
}

func CachedCodeArtifactListDomains(client AWSCodeArtifactClientInterface, accountID string, region string) ([]codeArtifactTypes.DomainSummary, error) {
	var PaginationControl *string
	var domains []codeArtifactTypes.DomainSummary
	cacheKey := fmt.Sprintf("%s-codeartifact-ListDomains-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]codeArtifactTypes.DomainSummary), nil
	}
	for {
		ListDomains, err := client.ListDomains(
			context.TODO(),
			&codeartifact.ListDomainsInput{
				NextToken: PaginationControl,
			},
			func(o *codeartifact.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return domains, err
		}

		domains = append(domains, ListDomains.Domains...)

		//pagination
		if ListDomains.NextToken == nil {
			break
		}
		PaginationControl = ListDomains.NextToken
	}

	internal.Cache.Set(cacheKey, domains, cache.DefaultExpiration)
	return domains, nil
}

func CachedCodeArtifactListRepositories(client AWSCodeArtifactClientInterface, accountID string, region string) ([]codeArtifactTypes.RepositorySummary, error) {
	var PaginationControl *string
	var repositories []codeArtifactTypes.RepositorySummary
	cacheKey := fmt.Sprintf("%s-codeartifact-ListRepositories-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]codeArtifactTypes.RepositorySummary), nil
	}
	for {
		ListRepositories, err := client.ListRepositories(
			context.TODO(),
			&codeartifact.ListRepositoriesInput{
				NextToken: PaginationControl,
			},
			func(o *codeartifact.Options) {
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
