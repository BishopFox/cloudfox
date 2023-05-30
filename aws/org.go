package aws

import (
	"fmt"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kyokomi/emoji"
	"github.com/sirupsen/logrus"
)

type OrgModule struct {
	OrganizationsClient sdk.OrganizationsClientInterface
	Caller              sts.GetCallerIdentityOutput
	AWSRegions          []string
	OutputFormat        string
	Goroutines          int
	AWSProfile          string
	SkipAdminCheck      bool
	WrapTable           bool
	DescribeOrgOutput   *types.Organization

	// Main module data
	Accounts       []Account
	Orgs           map[string]Org
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type Org struct {
	OrgId         string
	MgmtAccount   string
	ChildAccounts []Account
}

type Account struct {
	ProfileName         string
	isManagementAccount bool
	Name                string
	Id                  string
	Email               string
	Arn                 string
	Status              string
	OrgId               string
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
	m.DescribeOrgOutput, err = sdk.CachedOrganizationsDescribeOrganization(m.OrganizationsClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Errorf("Failed to describe organization: %s", err)
		return
	}
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
			m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), m.AWSProfile))
			//internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
			//m.writeLoot(m.output.FilePath, verbosity)
			o := internal.OutputClient{
				Verbosity:     verbosity,
				CallingModule: m.output.CallingModule,
				Table: internal.TableClient{
					Wrap: m.WrapTable,
				},
			}
			o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
				Header: m.output.Headers,
				Body:   m.output.Body,
				Name:   m.output.CallingModule,
			})
			o.PrefixIdentifier = m.AWSProfile
			o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), m.AWSProfile))
			o.WriteFullOutput(o.Table.TableFiles, nil)
			//m.writeLoot(o.Table.DirectoryName, verbosity)
			fmt.Printf("[%s][%s] %d accounts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), len(m.output.Body))
			fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

		}
	}
}

func (m *OrgModule) ProcessMultipleAccounts(AWSProfiles []string, version string) {
	var seenOrgs []string

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan Account)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	// Create a channel to signal to stop
	go m.Receiver(dataReceiver, receiverDone)

	for _, profile := range AWSProfiles {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.FindMgmtAccounts(profile, version, wg, semaphore, dataReceiver)

		wg.Wait()

		// Send a message to the spinner goroutine to close the channel and stop
		spinnerDone <- true
		<-spinnerDone
		receiverDone <- true
		<-receiverDone

		orgId := aws.ToString(m.DescribeOrgOutput.Id)
		// if this orgId is not in seenOrgs, add it to seenOrgs
		if !internal.Contains(orgId, seenOrgs) {
			seenOrgs = append(seenOrgs, orgId)
			// add this org to the Orgs map
			Org := Org{
				OrgId: orgId,
			}
			m.Orgs[orgId] = Org

		} else {
			continue
		}

		isMgmtAccount := m.IsManagementAccount(m.DescribeOrgOutput, aws.ToString(m.Caller.Account))
		if isMgmtAccount {
			mgmtAccount := aws.ToString(m.Caller.Account)
			fmt.Printf("[%s] Found an Organization Management Account: %s\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)), mgmtAccount)
			//mgmtAccounts[mgmtAccount] = append(mgmtAccounts[mgmtAccount], profile)
		}
	}
}

func (m *OrgModule) Receiver(receiver chan Account, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Accounts = append(m.Accounts, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *OrgModule) FindMgmtAccounts(profile string, version string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Account) {
	var err error

	DescribeOrganization, err := sdk.CachedOrganizationsDescribeOrganization(m.OrganizationsClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Errorf("Failed to describe organization: %s", err)
		m.CommandCounter.Error++
		return
	}

	dataReceiver <- Account{
		isManagementAccount: m.IsManagementAccount(DescribeOrganization, aws.ToString(m.Caller.Account)),
		Name:                aws.ToString(m.Caller.Account),
		Id:                  aws.ToString(m.Caller.Account),
		Status:              "ACTIVE",
		Email:               aws.ToString(m.Caller.Account),
		OrgId:               aws.ToString(DescribeOrganization.Id),
		Arn:                 aws.ToString(m.Caller.Account),
	}

}

func (m *OrgModule) IsManagementAccount(Organization *types.Organization, account string) bool {
	// Check if the account is the management account
	// https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html
	if aws.ToString(Organization.MasterAccountId) == account {
		return true
	}
	return false
}

func (m *OrgModule) addOrgAccounts() {
	accounts, err := sdk.CachedOrganizationsListAccounts(m.OrganizationsClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
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
	DescribeOrganization, err := sdk.CachedOrganizationsDescribeOrganization(m.OrganizationsClient, aws.ToString(m.Caller.Account))
	if err != nil {
		sharedLogger.Errorf("Failed to describe organization: %s", err)
		m.CommandCounter.Error++
		return
	}
	m.Accounts = append(m.Accounts, Account{
		isManagementAccount: true,
		Name:                "Mgmt Account",
		Id:                  aws.ToString(DescribeOrganization.MasterAccountId),
		Email:               aws.ToString(DescribeOrganization.MasterAccountEmail),
		Arn:                 aws.ToString(DescribeOrganization.MasterAccountArn),
		Status:              "ACTIVE",
	})
	m.Accounts = append(m.Accounts, Account{
		isManagementAccount: false,
		Name:                "This account",
		Id:                  aws.ToString(m.Caller.Account),
		Email:               "Unkonwn",
		Arn:                 aws.ToString(m.Caller.Arn),
		Status:              "ACTIVE",
	})
}

func (m *OrgModule) IsCallerAccountPartOfAnOrg() bool {
	DescribeOrgOutput, err := sdk.CachedOrganizationsDescribeOrganization(m.OrganizationsClient, aws.ToString(m.Caller.Account))
	if err != nil {
		sharedLogger.Errorf("Failed to describe organization: %s", err)
		return false
	} else {
		m.DescribeOrgOutput = DescribeOrgOutput
	}
	return true
}
