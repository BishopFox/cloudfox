package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenaTypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/patrickmn/go-cache"
)

type AWSAthenaClientInterface interface {
	ListDataCatalogs(context.Context, *athena.ListDataCatalogsInput, ...func(*athena.Options)) (*athena.ListDataCatalogsOutput, error)
	ListDatabases(context.Context, *athena.ListDatabasesInput, ...func(*athena.Options)) (*athena.ListDatabasesOutput, error)
}

func init() {
	gob.Register([]athenaTypes.DataCatalogSummary{})
}

func CachedAthenaListDataCatalogs(client AWSAthenaClientInterface, accountID string, region string) ([]athenaTypes.DataCatalogSummary, error) {
	var PaginationControl *string
	var dataCatalogs []athenaTypes.DataCatalogSummary
	cacheKey := fmt.Sprintf("%s-athena-ListDataCatalogs-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]athenaTypes.DataCatalogSummary), nil
	}
	for {
		ListDataCatalogs, err := client.ListDataCatalogs(
			context.TODO(),
			&athena.ListDataCatalogsInput{
				NextToken: PaginationControl,
			},
			func(o *athena.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return dataCatalogs, err
		}

		dataCatalogs = append(dataCatalogs, ListDataCatalogs.DataCatalogsSummary...)

		//pagination
		if ListDataCatalogs.NextToken == nil {
			break
		}
		PaginationControl = ListDataCatalogs.NextToken
	}

	internal.Cache.Set(cacheKey, dataCatalogs, cache.DefaultExpiration)
	return dataCatalogs, nil
}

func CachedAthenaListDatabases(client AWSAthenaClientInterface, accountID string, region string, catalogName string) ([]string, error) {
	var PaginationControl *string
	var databases []string
	cacheKey := fmt.Sprintf("%s-athena-ListDatabases-%s-%s", accountID, region, catalogName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]string), nil
	}
	for {
		ListDatabases, err := client.ListDatabases(
			context.TODO(),
			&athena.ListDatabasesInput{
				CatalogName: &catalogName,
				NextToken:   PaginationControl,
			},
			func(o *athena.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return databases, err
		}

		for _, database := range ListDatabases.DatabaseList {
			databases = append(databases, *database.Name)
		}

		//pagination
		if ListDatabases.NextToken == nil {
			break
		}
		PaginationControl = ListDatabases.NextToken
	}

	internal.Cache.Set(cacheKey, databases, cache.DefaultExpiration)
	return databases, nil
}
