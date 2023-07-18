package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datapipeline"
	dataPipelineTypes "github.com/aws/aws-sdk-go-v2/service/datapipeline/types"
)

type MockedDataPipelineClient struct {
}

func (m *MockedDataPipelineClient) ListPipelines(ctx context.Context, input *datapipeline.ListPipelinesInput, options ...func(*datapipeline.Options)) (*datapipeline.ListPipelinesOutput, error) {
	return &datapipeline.ListPipelinesOutput{
		PipelineIdList: []dataPipelineTypes.PipelineIdName{
			{
				Id:   aws.String("pipeline1"),
				Name: aws.String("pipeline1"),
			},
			{
				Id:   aws.String("pipeline2"),
				Name: aws.String("pipeline2"),
			},
		},
	}, nil
}
