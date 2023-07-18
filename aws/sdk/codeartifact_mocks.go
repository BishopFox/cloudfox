package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
	codeArtifactTypes "github.com/aws/aws-sdk-go-v2/service/codeartifact/types"
)

type MockedAWSCodeArtifactClient struct {
}

func (m *MockedAWSCodeArtifactClient) ListRepositories(ctx context.Context, input *codeartifact.ListRepositoriesInput, options ...func(*codeartifact.Options)) (*codeartifact.ListRepositoriesOutput, error) {
	return &codeartifact.ListRepositoriesOutput{
		NextToken: nil,
		Repositories: []codeArtifactTypes.RepositorySummary{
			{
				Name:       aws.String("repo1"),
				Arn:        aws.String("arn:aws:codeartifact:us-east-1:123456789012:repository/repo1"),
				DomainName: aws.String("domain1"),
			},
			{
				Name:       aws.String("repo2"),
				Arn:        aws.String("arn:aws:codeartifact:us-east-1:123456789012:repository/repo2"),
				DomainName: aws.String("domain1"),
			},
		},
	}, nil
}

func (m *MockedAWSCodeArtifactClient) ListDomains(ctx context.Context, input *codeartifact.ListDomainsInput, options ...func(*codeartifact.Options)) (*codeartifact.ListDomainsOutput, error) {
	return &codeartifact.ListDomainsOutput{
		NextToken: nil,
		Domains: []codeArtifactTypes.DomainSummary{
			{
				Name: aws.String("domain1"),
				Arn:  aws.String("arn:aws:codeartifact:us-east-1:123456789012:domain/domain1"),
			},
			{
				Name: aws.String("domain2"),
				Arn:  aws.String("arn:aws:codeartifact:us-east-1:123456789012:domain/domain2"),
			},
		},
	}, nil
}
