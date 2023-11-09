package aws

import (
	"fmt"

	"github.com/BishopFox/cloudfox/aws/graph/ingester/schema/models"
	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type GraphCommand struct {

	// General configuration data
	Caller             sts.GetCallerIdentityOutput
	AWSRegions         []string
	Goroutines         int
	AWSProfile         string
	WrapTable          bool
	AWSOutputType      string
	AWSTableCols       string
	Verbosity          int
	AWSOutputDirectory string
	AWSConfig          aws.Config

	// Main module data
	// Used to store output data for pretty printing
	output internal.OutputData2

	modLog *logrus.Entry
}

func init() {
	// initialize org client for graph command

}

func (m *GraphCommand) RunGraphCommand() {

	// These struct values are used by the output module
	m.output.Verbosity = m.Verbosity
	m.output.Directory = m.AWSOutputDirectory
	m.output.CallingModule = "graph"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	m.modLog.Info("Generating graph")

	m.collectDataForGraph()

}

func (m *GraphCommand) collectDataForGraph() {
	//OrganizationsCommandClient := InitOrgClient(m.AWSConfig)
	OrganizationsCommandClient := InitOrgClient(m.AWSConfig)
	DescribeOrgOutput, err := sdk.CachedOrganizationsDescribeOrganization(OrganizationsCommandClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Fatal(err)
	}
	if DescribeOrgOutput.MasterAccountId == nil {
		m.modLog.Fatal("Organization is not configured")
	}
	if aws.ToString(DescribeOrgOutput.MasterAccountId) != aws.ToString(m.Caller.Account) {
		m.modLog.Fatal("You must run this command from the master account")
	}
	ListAccounts, err := sdk.CachedOrganizationsListAccounts(OrganizationsCommandClient, aws.ToString(DescribeOrgOutput.MasterAccountId))
	if err != nil {
		m.modLog.Fatal(err)
	}
	for _, account := range ListAccounts {
		var isMgmtAccount bool
		var isChildAccount bool
		m.modLog.Info("Account: ", aws.ToString(account.Name))
		if aws.ToString(DescribeOrgOutput.MasterAccountId) == aws.ToString(m.Caller.Account) {
			isMgmtAccount = false
		} else {
			isMgmtAccount = true
		}
		if DescribeOrgOutput.MasterAccountId == nil {
			isChildAccount = false
		} else {
			isChildAccount = true
		}

		//create new object of type models.Account
		account := models.Account{
			Id:               aws.ToString(account.Id),
			Arn:              aws.ToString(account.Arn),
			Name:             aws.ToString(account.Name),
			Email:            aws.ToString(account.Email),
			Status:           string(account.Status),
			JoinedMethod:     string(account.JoinedMethod),
			JoinedTimestamp:  account.JoinedTimestamp.String(),
			IsOrgMgmt:        isMgmtAccount,
			IsChildAccount:   isChildAccount,
			OrgMgmtAccountID: aws.ToString(DescribeOrgOutput.MasterAccountId),
		}
		fmt.Println(account)
	}

}
