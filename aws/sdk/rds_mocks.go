package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type MOckedRDSClient struct {
}

func (m *MOckedRDSClient) DescribeDBInstances(ctx context.Context, input *rds.DescribeDBInstancesInput, options ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{
		DBInstances: []rdsTypes.DBInstance{
			{
				DBInstanceIdentifier: aws.String("db1"),
				Engine:               aws.String("postgres"),
				EngineVersion:        aws.String("13.3"),
				InstanceCreateTime:   aws.Time(time.Now()),
				MasterUsername:       aws.String("postgres"),
			},
			{
				DBInstanceIdentifier: aws.String("db2"),
				Engine:               aws.String("postgres"),
				EngineVersion:        aws.String("13.3"),
				InstanceCreateTime:   aws.Time(time.Now()),
				MasterUsername:       aws.String("postgres"),
			},
		},
	}, nil
}
