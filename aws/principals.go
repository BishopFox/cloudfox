package aws

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type IamPrincipalsModule struct {
	// General configuration data
	IAMClient sdk.AWSIAMClientInterface

	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSOutputType string
	AWSTableCols  string

	Goroutines int
	AWSProfile string
	WrapTable  bool

	// Main module data
	Users          []User
	Roles          []Role
	Groups         []Group
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type User struct {
	AWSService       string
	Type             string
	Arn              string
	Name             string
	AttachedPolicies []string
	InlinePolicies   []string
}

type Group struct {
	AWSService       string
	Type             string
	Arn              string
	Name             string
	AttachedPolicies []string
	InlinePolicies   []string
	AttachedUsers    []string
}

type Role struct {
	AWSService       string
	Type             string
	Arn              string
	Name             string
	AttachedPolicies []string
	InlinePolicies   []string
}

func (m *IamPrincipalsModule) PrintIamPrincipals(outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "principals"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating IAM Users and Roles for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	// wg := new(sync.WaitGroup)

	// done := make(chan bool)
	// go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, done)
	// wg.Add(1)
	// m.CommandCounter.Pending++
	//m.executeChecks(wg)
	// wg.Wait()
	// done <- true
	// <-done

	m.addIAMUsersToTable()
	m.addIAMRolesToTable()

	//fmt.Printf("\nAnalyzed Resources by Region\n\n")

	m.output.Headers = []string{
		"Service",
		"Type",
		"Name",
		"Arn",

		// "AttachedPolicies",
		// "InlinePolicies",
	}

	//Table rows
	for i := range m.Users {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Users[i].AWSService,
				m.Users[i].Type,
				m.Users[i].Name,
				m.Users[i].Arn,

				// m.Users[i].AttachedPolicies,
				// m.Users[i].InlinePolicies,
			},
		)

	}

	for i := range m.Roles {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Roles[i].AWSService,
				m.Roles[i].Type,
				m.Roles[i].Name,
				m.Roles[i].Arn,

				// m.Roles[i].AttachedPolicies,
				// m.Roles[i].InlinePolicies,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

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
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		//m.writeLoot(o.Table.DirectoryName, verbosity)
		fmt.Printf("[%s][%s] %s IAM principals found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No IAM principals found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

/* UNUSED CODE BLOCK - PLEASE REVIEW AND DELETE IF APPLICABLE
func (m *IamPrincipalsModule) executeChecks(wg *sync.WaitGroup) {
	defer wg.Done()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	m.getIAMUsers()
	m.getIAMRoles()
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
}
*/

func (m *IamPrincipalsModule) addIAMUsersToTable() {
	var AWSService = "IAM"
	var IAMtype = "User"
	var attachedPolicies []string
	var inlinePolicies []string

	ListUsers, err := sdk.CachedIamListUsers(m.IAMClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	for _, user := range ListUsers {
		arn := user.Arn
		name := user.UserName

		m.Users = append(
			m.Users,
			User{
				AWSService:       AWSService,
				Arn:              aws.ToString(arn),
				Name:             aws.ToString(name),
				Type:             IAMtype,
				AttachedPolicies: attachedPolicies,
				InlinePolicies:   inlinePolicies,
			})
	}

}

func (m *IamPrincipalsModule) addIAMRolesToTable() {

	//var totalRoles int
	var AWSService = "IAM"
	var IAMtype = "Role"
	var attachedPolicies []string
	var inlinePolicies []string

	ListRoles, err := sdk.CachedIamListRoles(m.IAMClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	for _, role := range ListRoles {
		arn := role.Arn
		name := role.RoleName

		m.Roles = append(
			m.Roles,
			Role{
				AWSService:       AWSService,
				Arn:              aws.ToString(arn),
				Name:             aws.ToString(name),
				Type:             IAMtype,
				AttachedPolicies: attachedPolicies,
				InlinePolicies:   inlinePolicies,
			})
	}

}
