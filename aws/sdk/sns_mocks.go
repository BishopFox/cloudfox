package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snsTypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
)

type MockedSNSClient struct {
}

func (m *MockedSNSClient) ListTopics(ctx context.Context, input *sns.ListTopicsInput, options ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	return &sns.ListTopicsOutput{
		Topics: []snsTypes.Topic{
			{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:topic1"),
			},
			{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:topic2"),
			},
		},
	}, nil
}

func (m *MockedSNSClient) ListSubscriptionsByTopic(ctx context.Context, input *sns.ListSubscriptionsByTopicInput, options ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error) {
	return &sns.ListSubscriptionsByTopicOutput{
		Subscriptions: []snsTypes.Subscription{
			{
				SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:topic1:sub1"),
			},
			{
				SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:topic1:sub2"),
			},
		},
	}, nil
}

func (m *MockedSNSClient) ListSubscriptions(ctx context.Context, input *sns.ListSubscriptionsInput, options ...func(*sns.Options)) (*sns.ListSubscriptionsOutput, error) {
	return &sns.ListSubscriptionsOutput{
		Subscriptions: []snsTypes.Subscription{
			{
				SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:topic1:sub1"),
			},
			{
				SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:topic1:sub2"),
			},
		},
	}, nil
}

func (m *MockedSNSClient) GetTopicAttributes(ctx context.Context, input *sns.GetTopicAttributesInput, options ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	return &sns.GetTopicAttributesOutput{
		Attributes: map[string]string{
			"DisplayName": "topic1",
			"Policy":      `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"SNS:Publish","Resource":"arn:aws:sns:us-east-1:123456789012:topoic1","Condition":{"StringEquals":{"aws:sourceVpce":"vpce-1a2b3c4d"}}}]}`,
		},
	}, nil
}
