package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

type MockedKinesisClient struct {
}

func (m *MockedKinesisClient) ListStreams(ctx context.Context, input *kinesis.ListStreamsInput, options ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error) {
	return &kinesis.ListStreamsOutput{
		HasMoreStreams: aws.Bool(false),
		StreamNames: []string{
			"stream1",
			"stream2",
		},
	}, nil
}
