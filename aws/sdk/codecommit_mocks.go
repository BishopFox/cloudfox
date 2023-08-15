package sdk

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codecommit"
	codeCommitTypes "github.com/aws/aws-sdk-go-v2/service/codecommit/types"
)

// create mocks for codecommit ListRepositories

type MockedAWSCodeCommitClient struct {
}

func (m *MockedAWSCodeCommitClient) ListRepositories(ctx context.Context, input *codecommit.ListRepositoriesInput, options ...func(*codecommit.Options)) (*codecommit.ListRepositoriesOutput, error) {
	return &codecommit.ListRepositoriesOutput{
		NextToken: nil,
		Repositories: []codeCommitTypes.RepositoryNameIdPair{
			{
				RepositoryId:   aws.String("repo1"),
				RepositoryName: aws.String("repo1"),
			},
			{
				RepositoryId:   aws.String("repo2"),
				RepositoryName: aws.String("repo2"),
			},
		},
	}, nil
}
