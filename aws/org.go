package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type OrgModule struct {
	OrganizationsClient *organizations.Client
	Caller              sts.GetCallerIdentityOutput
	AWSRegions          []string
	OutputFormat        string
	Goroutines          int
	AWSProfile          string
	SkipAdminCheck      bool
	WrapTable           bool
	DescribeOrgOutput   *organizations.DescribeOrganizationOutput

	// Main module data
	Accounts       []Account
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type OrganizationsClientInterface interface {
	ListAccounts(ctx context.Context, params *organizations.ListAccountsInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
}

type Account struct {
	isManagementAccount bool
	Name                string
	Id                  string
	Email               string
	Arn                 string
	Status              string
}

func (m *OrgModule) PrintOrgAccounts(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	var err error
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "org"

	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Checking if account %s is the management account in an organization.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	m.DescribeOrgOutput, err = m.DescribeOrganization()
	if err != nil {
		m.modLog.Errorf("Failed to describe organization: %s", err)
		fmt.Printf("[%s][%s] Account %s is either not associated with an organization, or you do not have the organizations:DescribeOrganization permission.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	} else {

		if m.IsManagementAccount(m.DescribeOrgOutput, aws.ToString(m.Caller.Account)) {
			m.addOrgAccounts()
		} else {
			m.addOrgAccount()
			//fmt.Printf("[%s][%s] Account %s is not the management account in an organization %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
		}

		m.output.Headers = []string{
			"Name",
			"ID",
			"isManagementAccount?",
			"Status",
			"Email",
		}

		// Table rows

		for i := range m.Accounts {
			m.output.Body = append(
				m.output.Body,
				[]string{
					m.Accounts[i].Name,
					m.Accounts[i].Id,
					strconv.FormatBool(m.Accounts[i].isManagementAccount),
					m.Accounts[i].Status,
					m.Accounts[i].Email,
				},
			)
		}

		if len(m.output.Body) > 0 {
			m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
			internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
			//m.writeLoot(m.output.FilePath, verbosity)
			fmt.Printf("[%s][%s] %d accounts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), len(m.output.Body))
			fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

		}
	}
}

// need to rework this to make it more efficient. It's currently making a call to describe organization for each account
func (m *OrgModule) IsManagementAccount(DescribeOrganization *organizations.DescribeOrganizationOutput, account string) bool {
	// Check if the account is the management account
	// https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html
	if aws.ToString(DescribeOrganization.Organization.MasterAccountId) == account {
		return true
	}
	return false
}

func (m *OrgModule) addOrgAccounts() {
	accounts, err := m.listAccounts()
	if err != nil {
		m.modLog.Errorf("Failed to list accounts: %s", err)
		return
	}
	for _, account := range accounts {
		m.Accounts = append(m.Accounts, Account{
			isManagementAccount: m.IsManagementAccount(m.DescribeOrgOutput, aws.ToString(account.Id)),
			Name:                aws.ToString(account.Name),
			Id:                  aws.ToString(account.Id),
			Email:               aws.ToString(account.Email),
			Arn:                 aws.ToString(account.Arn),
			Status:              string(account.Status),
		})
	}
}

func (m *OrgModule) addOrgAccount() {
	DescribeOrganization, err := m.DescribeOrganization()
	if err != nil {
		m.modLog.Errorf("Failed to describe organization: %s", err)
	}
	m.Accounts = append(m.Accounts, Account{
		isManagementAccount: true,
		Name:                "Unkown",
		Id:                  aws.ToString(DescribeOrganization.Organization.MasterAccountId),
		Email:               aws.ToString(DescribeOrganization.Organization.MasterAccountEmail),
		Arn:                 aws.ToString(DescribeOrganization.Organization.MasterAccountArn),
		Status:              "ACTIVE",
	})
}

func (m *OrgModule) listAccounts() ([]types.Account, error) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var accounts []types.Account

	for {
		ListAccounts, err := m.OrganizationsClient.ListAccounts(
			context.TODO(),
			&organizations.ListAccountsInput{
				NextToken: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		accounts = append(accounts, ListAccounts.Accounts...)

		if ListAccounts.NextToken != nil {
			PaginationControl = ListAccounts.NextToken
		} else {
			PaginationControl = nil
			break
		}

	}
	return accounts, nil
}

func (m *OrgModule) DescribeOrganization() (*organizations.DescribeOrganizationOutput, error) {
	return m.OrganizationsClient.DescribeOrganization(context.TODO(), &organizations.DescribeOrganizationInput{})
}

func (m *OrgModule) IsCallerAccountPartofAnOrg() bool {
	var err error
	m.DescribeOrgOutput, err = m.DescribeOrganization()
	if err != nil {
		m.modLog.Errorf("Failed to describe organization: %s", err)
		return false
	}
	return true
}
