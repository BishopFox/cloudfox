package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	elasticbeanstalkTypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type AWSElasticBeanstalkClientInterface interface {
	DescribeApplications(context.Context, *elasticbeanstalk.DescribeApplicationsInput, ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeApplicationsOutput, error)
}

func init() {
	gob.Register([]elasticbeanstalkTypes.ApplicationDescription{})
}

func CachedElasticBeanstalkDescribeApplications(client AWSElasticBeanstalkClientInterface, accountID string, region string) ([]elasticbeanstalkTypes.ApplicationDescription, error) {
	var applications []elasticbeanstalkTypes.ApplicationDescription
	cacheKey := fmt.Sprintf("%s-elasticbeanstalk-DescribeApplications-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "elasticbeanstalk:DescribeApplications",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]elasticbeanstalkTypes.ApplicationDescription), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "elasticbeanstalk:DescribeApplications",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	DescribeApplications, err := client.DescribeApplications(
		context.TODO(),
		&elasticbeanstalk.DescribeApplicationsInput{},
		func(o *elasticbeanstalk.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return applications, err
	}

	applications = append(applications, DescribeApplications.Applications...)
	internal.Cache.Set(cacheKey, applications, cache.DefaultExpiration)
	return applications, nil
}
