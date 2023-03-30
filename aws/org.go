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
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "org"

	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Checking if account %s is the management account in an organization %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	// wg := new(sync.WaitGroup)
	// semaphore := make(chan struct{}, m.Goroutines)

	// // Create a channel to signal the spinner aka task status goroutine to finish
	// spinnerDone := make(chan bool)
	// //fire up the the task status spinner/updated
	// go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	// //create a channel to receive the objects
	// dataReceiver := make(chan Project)

	// // Create a channel to signal to stop
	// receiverDone := make(chan bool)

	// go m.Receiver(dataReceiver, receiverDone)

	// // for _, region := range m.AWSRegions {
	// // 	wg.Add(1)
	// // 	m.CommandCounter.Pending++
	// // 	go m.executeChecks(region, wg, semaphore, dataReceiver)

	// // }

	// wg.Wait()

	// // Send a message to the spinner goroutine to close the channel and stop
	// spinnerDone <- true
	// <-spinnerDone
	// receiverDone <- true
	// <-receiverDone

	m.addOrgAccounts()

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

	} else {
		fmt.Printf("[%s][%s] No accounts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *OrgModule) addOrgAccounts() {
	accounts, err := m.listAccounts()
	if err != nil {
		m.modLog.Errorf("Failed to list accounts: %s", err)
		return
	}
	for _, account := range accounts {
		m.Accounts = append(m.Accounts, Account{
			isManagementAccount: false,
			Name:                aws.ToString(account.Name),
			Id:                  aws.ToString(account.Id),
			Email:               aws.ToString(account.Email),
			Arn:                 aws.ToString(account.Arn),
			Status:              string(account.Status),
		})
	}
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
