package sdk

import (
	"context"
	"encoding/gob"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfrontTypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type AWSCloudFrontClientInterface interface {
	ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
}

func init() {
	gob.Register([]cloudfrontTypes.DistributionSummary{})
	gob.Register(cloudfrontTypes.DistributionSummary{})
}

func CachedCloudFrontListDistributions(CloudFrontClient AWSCloudFrontClientInterface, accountID string) ([]cloudfrontTypes.DistributionSummary, error) {
	var PaginationControl *string
	var distributions []cloudfrontTypes.DistributionSummary
	cacheKey := "cloudfront-ListDistributions-" + accountID
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "cloudfront:ListDistributions",
			"account": accountID,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]cloudfrontTypes.DistributionSummary), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "cloudfront:ListDistributions",
		"account": accountID,
		"cache":   "miss",
	}).Info("AWS API call")

	for {
		ListDistributions, err := CloudFrontClient.ListDistributions(
			context.TODO(),
			&cloudfront.ListDistributionsInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		distributions = append(distributions, ListDistributions.DistributionList.Items...)

		// Pagination control.
		if ListDistributions.DistributionList.NextMarker != nil {
			PaginationControl = ListDistributions.DistributionList.NextMarker
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, distributions, cache.DefaultExpiration)
	return distributions, nil
}
