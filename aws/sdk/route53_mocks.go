package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53Types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type MockedRoute53Client struct {
}

func (m *MockedRoute53Client) ListHostedZones(ctx context.Context, input *route53.ListHostedZonesInput, options ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return &route53.ListHostedZonesOutput{
		HostedZones: []route53Types.HostedZone{
			{
				Id:                     aws.String("/hostedzone/zone1"),
				Name:                   aws.String("zone1"),
				ResourceRecordSetCount: aws.Int64(3),
			},
			{
				Id:                     aws.String("/hostedzone/zone2"),
				Name:                   aws.String("zone2"),
				ResourceRecordSetCount: aws.Int64(3),
			},
		},
	}, nil
}

func (m *MockedRoute53Client) ListResourceRecordSets(ctx context.Context, input *route53.ListResourceRecordSetsInput, options ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	return &route53.ListResourceRecordSetsOutput{
		ResourceRecordSets: []route53Types.ResourceRecordSet{
			{
				Name: aws.String("zone1"),
				Type: route53Types.RRTypeSoa,
			},
			{
				Name: aws.String("zone1"),
				Type: route53Types.RRTypeNs,
			},
			{
				Name: aws.String("zone1"),
				Type: route53Types.RRTypeA,
				ResourceRecords: []route53Types.ResourceRecord{
					{
						Value: aws.String("unit-test"),
					},
				},
			},
			{
				Name: aws.String("zone2"),
				Type: route53Types.RRTypeSoa,
			},
			{
				Name: aws.String("zone2"),
				Type: route53Types.RRTypeNs,
			},
			{
				Name: aws.String("zone2"),
				Type: route53Types.RRTypeA,
				ResourceRecords: []route53Types.ResourceRecord{
					{
						Value: aws.String("unit-test"),
					},
				},
			},
		},
	}, nil
}
