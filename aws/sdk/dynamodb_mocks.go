package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type MockedAWSDynamoDBClient struct {
}

func (m *MockedAWSDynamoDBClient) ListTables() ([]string, error) {
	return []string{"table1", "table2"}, nil
}

func (m *MockedAWSDynamoDBClient) DescribeTable(ctx context.Context, input *dynamodb.DescribeTableInput, options ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	return &dynamodb.DescribeTableOutput{
		Table: &dynamodbTypes.TableDescription{
			TableName: input.TableName,
		},
	}, nil
}
