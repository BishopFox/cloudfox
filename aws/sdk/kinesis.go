package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type AWSKinesisClientInterface interface {
	ListStreams(context.Context, *kinesis.ListStreamsInput, ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error)
}

func init() {
	gob.Register([]string{})
}

func CachedKinesisListStreams(client AWSKinesisClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var streams []string
	cacheKey := fmt.Sprintf("%s-kinesis-ListStreams-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "kinesis:ListStreams",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]string), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "kinesis:ListStreams",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		ListStreams, err := client.ListStreams(
			context.TODO(),
			&kinesis.ListStreamsInput{
				NextToken: PaginationControl,
			},
			func(o *kinesis.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return streams, err
		}

		streams = append(streams, ListStreams.StreamNames...)

		//pagination
		if ListStreams.NextToken == nil {
			break
		}
		PaginationControl = ListStreams.NextToken
	}

	internal.Cache.Set(cacheKey, streams, cache.DefaultExpiration)
	return streams, nil
}
