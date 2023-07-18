package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	openSearchTypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
)

type MockedOpenSearchClient struct {
}

func (m *MockedOpenSearchClient) ListDomainNames(ctx context.Context, input *opensearch.ListDomainNamesInput, options ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	return &opensearch.ListDomainNamesOutput{
		DomainNames: []openSearchTypes.DomainInfo{
			{
				DomainName: aws.String("domain1"),
				EngineType: openSearchTypes.EngineTypeOpenSearch,
			},
			{
				DomainName: aws.String("domain2"),
				EngineType: openSearchTypes.EngineTypeElasticsearch,
			},
		},
	}, nil
}

func (m *MockedOpenSearchClient) DescribeDomainConfig(ctx context.Context, input *opensearch.DescribeDomainConfigInput, options ...func(*opensearch.Options)) (*opensearch.DescribeDomainConfigOutput, error) {
	return &opensearch.DescribeDomainConfigOutput{
		DomainConfig: &openSearchTypes.DomainConfig{
			EngineVersion: &openSearchTypes.VersionStatus{
				Options: aws.String("OpenSearch-1.1"),
				Status: &openSearchTypes.OptionStatus{
					PendingDeletion: aws.Bool(false),
				},
			},
			ClusterConfig: &openSearchTypes.ClusterConfigStatus{
				Options: &openSearchTypes.ClusterConfig{
					DedicatedMasterCount:   aws.Int32(3),
					DedicatedMasterEnabled: aws.Bool(true),
					InstanceCount:          aws.Int32(3),
					WarmCount:              aws.Int32(3),
					WarmEnabled:            aws.Bool(true),
				},
			},
			DomainEndpointOptions: &openSearchTypes.DomainEndpointOptionsStatus{
				Options: &openSearchTypes.DomainEndpointOptions{
					EnforceHTTPS: aws.Bool(true),
				},
			},
		},
	}, nil
}

func (m *MockedOpenSearchClient) DescribeDomain(ctx context.Context, input *opensearch.DescribeDomainInput, options ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error) {
	return &opensearch.DescribeDomainOutput{
		DomainStatus: &openSearchTypes.DomainStatus{
			DomainName: aws.String("domain1"),
			Endpoint:   aws.String("https://domain1.us-east-1.es.amazonaws.com"),
		},
	}, nil
}
