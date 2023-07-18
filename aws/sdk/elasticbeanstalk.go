package sdk

import (
	"context"
	"encoding/gob"

	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	elasticbeanstalkTypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
)

type AWSElasticBeanstalkClientInterface interface {
	DescribeApplications(context.Context, *elasticbeanstalk.DescribeApplicationsInput, ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeApplicationsOutput, error)
}

func init() {
	gob.Register([]elasticbeanstalkTypes.ApplicationDescription{})
}

func CachedElasticBeanstalkDescribeApplications(client AWSElasticBeanstalkClientInterface, accountID string, region string) ([]elasticbeanstalkTypes.ApplicationDescription, error) {
	var applications []elasticbeanstalkTypes.ApplicationDescription
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
	return applications, nil
}
