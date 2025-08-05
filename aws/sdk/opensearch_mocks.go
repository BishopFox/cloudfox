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
	domainConfigMap := map[string]*openSearchTypes.DomainConfig{
		"domain1": {
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
			AdvancedSecurityOptions: &openSearchTypes.AdvancedSecurityOptionsStatus{
				Options: &openSearchTypes.AdvancedSecurityOptions{
					Enabled: aws.Bool(true),
				},
			},
		},
		"domain2": {
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
			AdvancedSecurityOptions: &openSearchTypes.AdvancedSecurityOptionsStatus{
				Options: &openSearchTypes.AdvancedSecurityOptions{
					Enabled: aws.Bool(false),
				},
			},
		},
	}

	return &opensearch.DescribeDomainConfigOutput{
		DomainConfig: domainConfigMap[*input.DomainName],
	}, nil
}

func (m *MockedOpenSearchClient) DescribeDomain(ctx context.Context, input *opensearch.DescribeDomainInput, options ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error) {
	domainStatusMap := map[string]*openSearchTypes.DomainStatus{
		"domain1": {
			DomainName:     aws.String("domain1"),
			Endpoint:       aws.String("https://domain1.us-east-1.es.amazonaws.com"),
			ARN:            aws.String("arn:aws:es:us-east-1:123456789012:domain/domain1"),
			AccessPolicies: aws.String(`{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":[\"es:ESHttpGet\",\"es:ESHttpHead\",\"es:ESHttpPost\"],\"Resource\":\"*\",\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"192.168.1.100/32\"}}}]}`),
		},
		"domain2": {
			DomainName:     aws.String("domain2"),
			Endpoint:       aws.String("https://domain2.us-east-1.es.amazonaws.com"),
			ARN:            aws.String("arn:aws:es:us-east-1:123456789012:domain/domain2"),
			AccessPolicies: aws.String(`{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":[\"es:ESHttpGet\",\"es:ESHttpHead\",\"es:ESHttpPost\"],\"Resource\":\"*\"}]}`),
		},
	}

	return &opensearch.DescribeDomainOutput{
		DomainStatus: domainStatusMap[*input.DomainName],
	}, nil
}
