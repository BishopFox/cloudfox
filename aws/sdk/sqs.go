package sdk

import (
	"context"
	"encoding/gob"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/patrickmn/go-cache"
)

type AWSSQSClientInterface interface {
	ListQueues(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
}

func init() {
	gob.Register([]string{})
}

func CachedSQSListQueues(SQSClient AWSSQSClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var queues []string
	cacheKey := "sqs-ListQueues-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached SQS queues data")
		return cached.([]string), nil
	}

	for {
		ListQueues, err := SQSClient.ListQueues(
			context.TODO(),
			&sqs.ListQueuesInput{
				NextToken: PaginationControl,
			},
			func(o *sqs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		queues = append(queues, ListQueues.QueueUrls...)

		// Pagination control.
		if ListQueues.NextToken != nil {
			PaginationControl = ListQueues.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, queues, cache.DefaultExpiration)
	return queues, nil
}
