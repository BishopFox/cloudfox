package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	glueTypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
)

type MockedGlueClient struct {
}

func (m *MockedGlueClient) ListDevEndpoints(ctx context.Context, input *glue.ListDevEndpointsInput, options ...func(*glue.Options)) (*glue.ListDevEndpointsOutput, error) {
	return &glue.ListDevEndpointsOutput{
		DevEndpointNames: []string{
			"devendpoint1",
			"devendpoint2",
		},
	}, nil
}

func (m *MockedGlueClient) ListJobs(ctx context.Context, input *glue.ListJobsInput, options ...func(*glue.Options)) (*glue.ListJobsOutput, error) {
	return &glue.ListJobsOutput{
		JobNames: []string{
			"job1",
			"job2",
		},
	}, nil
}

func (m *MockedGlueClient) GetTables(ctx context.Context, input *glue.GetTablesInput, options ...func(*glue.Options)) (*glue.GetTablesOutput, error) {
	return &glue.GetTablesOutput{
		TableList: []glueTypes.Table{
			{
				Name:         aws.String("table1"),
				DatabaseName: aws.String("database1"),
				Description:  aws.String("description1"),
				Parameters: map[string]string{
					"param1": "value1",
					"param2": "value2",
				},
			},
			{
				Name:         aws.String("table2"),
				DatabaseName: aws.String("database2"),
				Description:  aws.String("description2"),
				Parameters: map[string]string{
					"param1": "value1",
					"param2": "value2",
				},
			},
		},
	}, nil
}

func (m *MockedGlueClient) GetDatabases(ctx context.Context, input *glue.GetDatabasesInput, options ...func(*glue.Options)) (*glue.GetDatabasesOutput, error) {
	return &glue.GetDatabasesOutput{
		DatabaseList: []glueTypes.Database{
			{
				Name:        aws.String("database1"),
				Description: aws.String("description1"),
				LocationUri: aws.String("s3://bucket1"),
				Parameters: map[string]string{
					"param1": "value1",
					"param2": "value2",
				},
			},
			{
				Name:        aws.String("database2"),
				Description: aws.String("description2"),
				LocationUri: aws.String("s3://bucket2"),
				Parameters: map[string]string{
					"param1": "value1",
					"param2": "value2",
				},
			},
		},
	}, nil
}
