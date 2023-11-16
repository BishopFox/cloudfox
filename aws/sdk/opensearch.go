package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	openSearchTypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/patrickmn/go-cache"
)

type OpenSearchClientInterface interface {
	ListDomainNames(context.Context, *opensearch.ListDomainNamesInput, ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomainConfig(context.Context, *opensearch.DescribeDomainConfigInput, ...func(*opensearch.Options)) (*opensearch.DescribeDomainConfigOutput, error)
	DescribeDomain(context.Context, *opensearch.DescribeDomainInput, ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error)
}

func init() {
	gob.Register([]openSearchTypes.DomainInfo{})
	gob.Register(openSearchTypes.DomainConfig{})
	gob.Register(openSearchTypes.DomainStatus{})
}

// create CachedOpenSearchListDomainNames function that uses go-cache and pagination
func CachedOpenSearchListDomainNames(client OpenSearchClientInterface, accountID string, region string) ([]openSearchTypes.DomainInfo, error) {
	var domains []openSearchTypes.DomainInfo
	cacheKey := fmt.Sprintf("%s-opensearch-ListDomainNames-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]openSearchTypes.DomainInfo), nil
	}

	ListDomainNames, err := client.ListDomainNames(
		context.TODO(),
		&opensearch.ListDomainNamesInput{},
		func(o *opensearch.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return domains, err
	}

	domains = append(domains, ListDomainNames.DomainNames...)

	internal.Cache.Set(cacheKey, domains, cache.DefaultExpiration)
	return domains, nil
}

// create CachedOpenSearchDescribeDomainConfig function that uses go-cache and pagination and supports region option
func CachedOpenSearchDescribeDomainConfig(client OpenSearchClientInterface, accountID string, region string, domainName string) (openSearchTypes.DomainConfig, error) {
	var DomainConfig openSearchTypes.DomainConfig
	cacheKey := fmt.Sprintf("%s-opensearch-DescribeDomainConfig-%s-%s", accountID, region, domainName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(openSearchTypes.DomainConfig), nil
	}
	DescribeDomainConfig, err := client.DescribeDomainConfig(
		context.TODO(),
		&opensearch.DescribeDomainConfigInput{
			DomainName: &domainName,
		},
		func(o *opensearch.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return DomainConfig, err
	}

	DomainConfig = *DescribeDomainConfig.DomainConfig

	internal.Cache.Set(cacheKey, DomainConfig, cache.DefaultExpiration)
	return DomainConfig, nil
}

// create CachedOpenSearchDescribeDomain function that uses go-cache and pagination and supports region option
func CachedOpenSearchDescribeDomain(client OpenSearchClientInterface, accountID string, region string, domainName string) (openSearchTypes.DomainStatus, error) {
	var DomainStatus openSearchTypes.DomainStatus
	cacheKey := fmt.Sprintf("%s-opensearch-DescribeDomain-%s-%s", accountID, region, domainName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(openSearchTypes.DomainStatus), nil
	}
	DescribeDomain, err := client.DescribeDomain(
		context.TODO(),
		&opensearch.DescribeDomainInput{
			DomainName: &domainName,
		},
		func(o *opensearch.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return DomainStatus, err
	}

	DomainStatus = *DescribeDomain.DomainStatus

	internal.Cache.Set(cacheKey, DomainStatus, cache.DefaultExpiration)
	return DomainStatus, nil
}
