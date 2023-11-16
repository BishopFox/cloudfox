package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizationsTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

type MockedOrgClient struct {
}

func (m *MockedOrgClient) ListAccounts(ctx context.Context, input *organizations.ListAccountsInput, options ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	return &organizations.ListAccountsOutput{
		Accounts: []organizationsTypes.Account{
			{
				Arn:             aws.String("arn:aws:organizations::123456789012:account/o-exampleorgid/111111111111"),
				Email:           aws.String("unittesting@bishopfox.com"),
				Id:              aws.String("111111111111"),
				JoinedMethod:    organizationsTypes.AccountJoinedMethodInvited,
				JoinedTimestamp: aws.Time(time.Now()),
				Name:            aws.String("account1"),
				Status:          organizationsTypes.AccountStatusActive,
			},
			{
				Arn:             aws.String("arn:aws:organizations::123456789012:account/o-exampleorgid/222222222222"),
				Email:           aws.String("unittesting1@bishopfox.com"),
				Id:              aws.String("222222222222"),
				JoinedMethod:    organizationsTypes.AccountJoinedMethodCreated,
				JoinedTimestamp: aws.Time(time.Now()),
				Name:            aws.String("account2"),
				Status:          organizationsTypes.AccountStatusActive,
			},
		},
	}, nil

}

func (m *MockedOrgClient) DescribeOrganization(ctx context.Context, input *organizations.DescribeOrganizationInput, options ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return &organizations.DescribeOrganizationOutput{
		Organization: &organizationsTypes.Organization{
			Arn:                aws.String("arn:aws:organizations::123456789012:organization/o-exampleorgid"),
			FeatureSet:         organizationsTypes.OrganizationFeatureSetAll,
			Id:                 aws.String("o-exampleorgid"),
			MasterAccountArn:   aws.String("arn:aws:organizations::123456789012:account/o-exampleorgid/111111111111"),
			MasterAccountEmail: aws.String("unittesting1@bishopfox.com"),
			MasterAccountId:    aws.String("111111111111"),
		},
	}, nil
}
