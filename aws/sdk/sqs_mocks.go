package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type MockedSQSClient struct {
}

func (m *MockedSQSClient) ListQueues(ctx context.Context, input *sqs.ListQueuesInput, options ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	return &sqs.ListQueuesOutput{
		QueueUrls: []string{
			"https://sqs.us-east-1.amazonaws.com/123456789012/queue1",
			"https://sqs.us-east-1.amazonaws.com/123456789012/queue2",
		},
	}, nil
}

func (m *MockedSQSClient) GetQueueAttributes(ctx context.Context, input *sqs.GetQueueAttributesInput, options ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	return &sqs.GetQueueAttributesOutput{
		Attributes: map[string]string{
			"QueueArn": "arn:aws:sqs:us-east-1:123456789012:queue1",
			"Policy":   `{"Version": "2012-10-17","Id": "anyID","Statement": [{"Sid":"unconditionally_public","Effect": "Allow","Principal": {"AWS": "*"},"Action": "sqs:*","Resource": "arn:aws:sqs:*:123456789012:some-queue"}]}`,
		},
	}, nil
}
