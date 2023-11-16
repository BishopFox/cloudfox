package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	elasticbeanstalkTypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
)

type MockedElasticBeanstalkClient struct {
}

func (m *MockedElasticBeanstalkClient) DescribeApplications(ctx context.Context, input *elasticbeanstalk.DescribeApplicationsInput, options ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeApplicationsOutput, error) {
	return &elasticbeanstalk.DescribeApplicationsOutput{
		Applications: []elasticbeanstalkTypes.ApplicationDescription{
			{
				ApplicationName: aws.String("app1"),
				ApplicationArn:  aws.String("arn:aws:elasticbeanstalk:us-east-1:123456789012:application/app1"),
				ConfigurationTemplates: []string{
					"template1",
				},
			},
			{
				ApplicationName: aws.String("app2"),
				ApplicationArn:  aws.String("arn:aws:elasticbeanstalk:us-east-1:123456789012:application/app2"),
				ConfigurationTemplates: []string{
					"template2",
				},
			},
		},
	}, nil
}
