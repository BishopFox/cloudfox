package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqTypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/patrickmn/go-cache"
)

type MQClientInterface interface {
	ListBrokers(context.Context, *mq.ListBrokersInput, ...func(*mq.Options)) (*mq.ListBrokersOutput, error)
}

func init() {
	gob.Register([]mqTypes.BrokerSummary{})
}

// create CachedMQListBrokers function that uses go-cache and pagination
func CachedMQListBrokers(client MQClientInterface, accountID string, region string) ([]mqTypes.BrokerSummary, error) {
	var PaginationControl *string
	var brokers []mqTypes.BrokerSummary
	cacheKey := fmt.Sprintf("%s-mq-ListBrokers-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]mqTypes.BrokerSummary), nil
	}

	for {
		ListBrokers, err := client.ListBrokers(
			context.TODO(),
			&mq.ListBrokersInput{
				NextToken: PaginationControl,
			},
			func(o *mq.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return brokers, err
		}

		brokers = append(brokers, ListBrokers.BrokerSummaries...)

		//pagination
		if ListBrokers.NextToken == nil {
			break
		}
		PaginationControl = ListBrokers.NextToken
	}

	internal.Cache.Set(cacheKey, brokers, cache.DefaultExpiration)
	return brokers, nil
}
