package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamoDBTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/patrickmn/go-cache"
)

type DynamoDBClientInterface interface {
	ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

func RegisterDynamoDBTypes() {
	gob.Register([]string{})
	gob.Register(dynamoDBTypes.TableDescription{})
}

func CachedDynamoDBListTables(client DynamoDBClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var tables []string
	cacheKey := fmt.Sprintf("%s-dynamodb-ListTables-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]string), nil
	}
	for {
		ListTables, err := client.ListTables(
			context.TODO(),
			&dynamodb.ListTablesInput{
				ExclusiveStartTableName: PaginationControl,
			},
			func(o *dynamodb.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return tables, err
		}

		tables = append(tables, ListTables.TableNames...)

		//pagination
		if ListTables.LastEvaluatedTableName == nil {
			break
		}
		PaginationControl = ListTables.LastEvaluatedTableName
	}

	internal.Cache.Set(cacheKey, tables, cache.DefaultExpiration)
	return tables, nil
}

func CachedDynamoDBDescribeTable(client DynamoDBClientInterface, accountID string, region string, tableName string) (dynamoDBTypes.TableDescription, error) {
	var tableDescription dynamoDBTypes.TableDescription
	cacheKey := fmt.Sprintf("%s-dynamodb-DescribeTable-%s-%s", accountID, region, tableName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(dynamoDBTypes.TableDescription), nil
	}

	DescribeTable, err := client.DescribeTable(
		context.TODO(),
		&dynamodb.DescribeTableInput{
			TableName: &tableName,
		},
		func(o *dynamodb.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return tableDescription, err
	}
	tableDescription = *DescribeTable.Table

	internal.Cache.Set(cacheKey, tableDescription, cache.DefaultExpiration)
	return tableDescription, nil
}
