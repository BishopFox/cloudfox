package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type OrganizationsClientInterface interface {
	ListAccounts(ctx context.Context, params *organizations.ListAccountsInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
	DescribeOrganization(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
}

func init() {
	gob.Register([]orgTypes.Account{})
	//gob.Register(orgTypes.Organization{})
}

// create a CachedOrganizationsListAccounts function that uses go-cache and pagination and returns a list of accounts
func CachedOrganizationsListAccounts(client OrganizationsClientInterface, accountID string) ([]orgTypes.Account, error) {
	var PaginationControl *string
	var accounts []orgTypes.Account
	cacheKey := fmt.Sprintf("%s-organizations-ListAccounts", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "organizations:ListAccounts",
			"account": accountID,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]orgTypes.Account), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "organizations:ListAccounts",
		"account": accountID,
		"cache":   "miss",
	}).Info("AWS API call")

	for {
		ListAccounts, err := client.ListAccounts(
			context.TODO(),
			&organizations.ListAccountsInput{
				NextToken: PaginationControl,
			},
		)

		if err != nil {
			return accounts, err
		}

		accounts = append(accounts, ListAccounts.Accounts...)

		//pagination
		if ListAccounts.NextToken == nil {
			break
		}
		PaginationControl = ListAccounts.NextToken
	}
	internal.Cache.Set(cacheKey, accounts, cache.DefaultExpiration)

	return accounts, nil
}

// create a CachedOrganizationsDescribeOrganization function that uses go-cache and returns an organization
func CachedOrganizationsDescribeOrganization(client OrganizationsClientInterface, accountID string) (*orgTypes.Organization, error) {
	var organization *orgTypes.Organization
	cacheKey := fmt.Sprintf("%s-organizations-DescribeOrganization", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "organizations:DescribeOrganization",
			"account": accountID,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.(*orgTypes.Organization), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "organizations:DescribeOrganization",
		"account": accountID,
		"cache":   "miss",
	}).Info("AWS API call")

	DescribeOrganization, err := client.DescribeOrganization(
		context.TODO(),
		&organizations.DescribeOrganizationInput{},
	)

	if err != nil {
		return organization, err
	}

	organization = DescribeOrganization.Organization
	internal.Cache.Set(cacheKey, organization, cache.DefaultExpiration)

	return organization, nil
}
