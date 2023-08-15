package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticacheTypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
)

type MockedElasticacheClient struct {
}

func (m *MockedElasticacheClient) DescribeCacheClusters(ctx context.Context, input *elasticache.DescribeCacheClustersInput, options ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error) {
	return &elasticache.DescribeCacheClustersOutput{
		CacheClusters: []elasticacheTypes.CacheCluster{
			{
				CacheClusterId:            aws.String("test"),
				ARN:                       aws.String("arn:aws:elasticache:us-east-1:123456789012:cluster:myCluster"),
				Engine:                    aws.String("redis"),
				EngineVersion:             aws.String("6.x"),
				CacheNodeType:             aws.String("cache.t3.micro"),
				NumCacheNodes:             aws.Int32(1),
				CacheClusterStatus:        aws.String("available"),
				PreferredAvailabilityZone: aws.String("us-east-1a"),
				CacheSubnetGroupName:      aws.String("default"),
				ReplicationGroupId:        aws.String("test"),
				SecurityGroups: []elasticacheTypes.SecurityGroupMembership{
					{
						SecurityGroupId: aws.String("test"),
						Status:          aws.String("active"),
					},
				},

				AutoMinorVersionUpgrade:    true,
				PreferredMaintenanceWindow: aws.String("sun:05:00-sun:06:00"),
			},
		},
	}, nil
}
