package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfrontTypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

type MockedAWSCloudFrontClient struct {
}

func (m *MockedAWSCloudFrontClient) ListDistributions(ctx context.Context, input *cloudfront.ListDistributionsInput, options ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return &cloudfront.ListDistributionsOutput{
		DistributionList: &cloudfrontTypes.DistributionList{
			Items: []cloudfrontTypes.DistributionSummary{
				{
					Id: aws.String("distribution1"),
				},
				{
					Id: aws.String("distribution2"),
				},
			},
		},
	}, nil
}
