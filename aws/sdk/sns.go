package sdk

import (
	"context"
	"encoding/gob"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snsTypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/patrickmn/go-cache"
)

type AWSSNSClientInterface interface {
	ListTopics(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	ListSubscriptions(ctx context.Context, params *sns.ListSubscriptionsInput, optFns ...func(*sns.Options)) (*sns.ListSubscriptionsOutput, error)
	ListSubscriptionsByTopic(ctx context.Context, params *sns.ListSubscriptionsByTopicInput, optFns ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error)
}

func init() {
	gob.Register([]string{})
	gob.Register(snsTypes.Topic{})
	gob.Register(snsTypes.Subscription{})
}

func CachedSNSListTopics(SNSClient AWSSNSClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var topics []string
	cacheKey := "sns-ListTopics-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached SNS topics data")
		return cached.([]string), nil
	}

	for {
		ListTopics, err := SNSClient.ListTopics(
			context.TODO(),
			&sns.ListTopicsInput{
				NextToken: PaginationControl,
			},
			func(o *sns.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		for _, topic := range ListTopics.Topics {
			topics = append(topics, *topic.TopicArn)
		}

		// Pagination control.
		if ListTopics.NextToken != nil {
			PaginationControl = ListTopics.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, topics, cache.DefaultExpiration)

	return topics, nil
}

func CachedSNSListSubscriptions(SNSClient AWSSNSClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var subscriptions []string
	cacheKey := "sns-ListSubscriptions-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached SNS subscriptions data")
		return cached.([]string), nil
	}

	for {
		ListSubscriptions, err := SNSClient.ListSubscriptions(
			context.TODO(),
			&sns.ListSubscriptionsInput{
				NextToken: PaginationControl,
			},
			func(o *sns.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		for _, subscription := range ListSubscriptions.Subscriptions {
			subscriptions = append(subscriptions, *subscription.SubscriptionArn)
		}

		// Pagination control.
		if ListSubscriptions.NextToken != nil {
			PaginationControl = ListSubscriptions.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, subscriptions, cache.DefaultExpiration)

	return subscriptions, nil
}

func CachedSNSListSubscriptionsByTopic(SNSClient AWSSNSClientInterface, accountID string, region string, topicArn string) ([]string, error) {
	var PaginationControl *string
	var subscriptions []string
	cacheKey := "sns-ListSubscriptionsByTopic-" + accountID + "-" + region + "-" + topicArn
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached SNS subscriptions data")
		return cached.([]string), nil
	}

	for {
		ListSubscriptionsByTopic, err := SNSClient.ListSubscriptionsByTopic(
			context.TODO(),
			&sns.ListSubscriptionsByTopicInput{
				NextToken: PaginationControl,
				TopicArn:  &topicArn,
			},
			func(o *sns.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		for _, subscription := range ListSubscriptionsByTopic.Subscriptions {
			subscriptions = append(subscriptions, *subscription.SubscriptionArn)
		}

		// Pagination control.
		if ListSubscriptionsByTopic.NextToken != nil {
			PaginationControl = ListSubscriptionsByTopic.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, subscriptions, cache.DefaultExpiration)

	return subscriptions, nil
}
